"""Ongoing review: what changed since the advice, whether it still holds, what is due, and the successor case when it does not.

Advice already given is a sealed thing: a record, a recommendation and the state they rested on.
An ongoing review does not rewrite it. It asks, at one moment, what has moved: the client's
disclosed decision facts (a state diff with the life events the changes signal), the published
catalog (is the product still offered, do its cited facts still hold), suitability against the
current state, the serviceability verdict the strategy work passed in, the needs the facts now
call for, the authority the adviser holds, the fee arrangement, the implemented terms and the
disclosures given. Each answer is a check that holds, changed or could not be assessed; each
event with a date is a trigger with its severity; the outcome is the highest severity of the
lot. When the outcome is re-advice, the review receipt refuses to close without the successor
case that carries the new advice, linked back by ``predecessor_case_ref``; the successor opens at
intake with an incomplete fact find, because the state must be re-disclosed.

Everything is deterministic and reads sealed objects or plain tables. Nothing here recommends,
ranks, or computes serviceability; the serviceability verdict is passed in as a Mapping and the
suitability and needs rechecks reuse the engine's own functions.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, add_days, detached, iso, parsed, seal, sealed_digest, skip_digests, timestamp
from lightbulb.finance_advice_identity import AdviceIdentityModel as StrictModel
from lightbulb.finance_advice_catalog import Product, ProductCatalog, VerticalRegistry
from lightbulb.finance_advice_engine import AdvicePlan, ClientState, evaluate_suitability
from lightbulb.finance_advice_fact_find import fact_find_requirements
from lightbulb.finance_advice_licence import DEFAULT_EXPIRING_SOON_DAYS, DEFAULT_REGISTER_MAX_AGE_HOURS
from lightbulb.finance_advice_needs import assess_needs, needs_kind
from lightbulb.finance_advice_quotes import QUOTE_VALIDITY_DAYS
from lightbulb.finance_advice_record import ProductEvidence, RecordOfAdviceEvidence

REVIEW_SCHEMA = "lightbulb.finance_advice_review_assessment.v1"
STATE_DIFF_SCHEMA = "lightbulb.finance_advice_state_diff.v1"
CALENDAR_SCHEMA = "lightbulb.finance_advice_review_calendar.v1"
VERIFICATION_MAX_AGE_DAYS = DEFAULT_REGISTER_MAX_AGE_HOURS // 24
AUTHORITY_EXPIRING_DAYS = DEFAULT_EXPIRING_SOON_DAYS
FEE_RENEWAL_WINDOW_DAYS = 60
APPROVAL_AGEING_DAYS = 30
DEFAULT_CALENDAR_HORIZON_DAYS = 90
FORBIDDEN_REVIEW_KEYS = frozenset({"name", "first_name", "last_name", "full_name", "email", "phone", "mobile", "address", "street", "date_of_birth", "dob", "account_number", "policy_number", "member_number", "licence_number", "license_number", "drivers_licence", "driver_licence", "tax_file_number", "tfn", "sin", "social_insurance_number", "passport", "signature", "bsb", "iban", "card_number", "tenant_id", "company_id", "user_id", "client_id", "customer_id"})

# the decision facts the shortlist, the projection, the needs or the serviceability verdict rank on; a change is material
RANKED_FIELDS = frozenset({"amount", "lvr_percent", "term_years", "purpose", "residency", "age_band", "region", "income", "expenses", "debts", "dependants", "smoker", "occupation_class", "existing_cover", "holdings", "risk_profile"})

# a life event and the facts to re-ask; a table, not a detector
LIFE_EVENTS: dict[str, tuple[str, ...]] = {
    "marriage": ("dependants", "income", "existing_cover", "debts", "holdings", "cover_type"),
    "separation": ("dependants", "income", "debts", "existing_cover", "holdings", "cover_type", "amount"),
    "child": ("dependants", "income", "expenses", "existing_cover", "cover_type"),
    "job_change": ("income", "income_band", "occupation_class", "sick_leave_days", "affinity_groups"),
    "income_change": ("income", "income_band", "expenses", "savings"),
    "retirement": ("income", "income_band", "retirement_age", "pension_or_concession", "horizon_years", "risk_profile", "existing_cover"),
    "property_purchase": ("amount", "lvr_percent", "term_years", "purpose", "region", "debts", "transaction", "holdings"),
    "property_sale": ("amount", "lvr_percent", "purpose", "debts", "holdings", "region"),
    "inheritance": ("amount", "savings", "debts", "horizon_years", "risk_profile", "investor_classification"),
    "illness": ("smoker", "pre_existing_conditions", "occupation_class", "existing_cover", "sick_leave_days"),
    "relocation": ("region", "residency", "cover", "usage"),
    "new_debt": ("debts", "amount", "lvr_percent", "expenses", "holdings"),
}
# a changed fact signals the life events the adviser confirms with the client; the reverse of the table above, narrowed to unambiguous signals
_FIELD_SIGNALS: dict[str, tuple[str, ...]] = {
    "dependants": ("child",),
    "income": ("income_change",),
    "income_band": ("income_change",),
    "occupation_class": ("job_change",),
    "region": ("relocation",),
    "residency": ("relocation",),
    "jurisdiction": ("relocation",),
    "debts": ("new_debt",),
    "retirement_age": ("retirement",),
    "pension_or_concession": ("retirement",),
    "smoker": ("illness",),
    "pre_existing_conditions": ("illness",),
}
# the disclosures a presentation must have carried, per (jurisdiction, family); mirrors the engagement block's presentation-stage table
_PRESENTATION_DISCLOSURES: dict[tuple[str, str], tuple[str, ...]] = {("AU", "insurance"): ("product_disclosure_statement",), ("AU", "investments"): ("product_disclosure_statement",)}
_NEEDS_KINDS = frozenset({"life", "income_protection", "tpd", "trauma"})
_WITHDRAWN = frozenset({"withdrawn", "closed", "not_available", "unavailable"})
_STATE_FIELDS: tuple[str, ...] = ("jurisdiction", "objective", "amount", "lvr_percent", "term_years", "residency", "age_band", "income_band", "purpose", "region", "preferences")
_SEVERITY_RANK = {"note": 0, "confirm": 1, "readvice": 2}
_OUTCOME_RANK = {"advice_holds": 0, "adviser_confirms": 1, "client_re_disclosure_required": 2, "readvice_required": 3}

TriggerKind = Literal["review_due", "fact_changed", "life_event", "product_fact_changed", "product_withdrawn", "quote_expired", "authority_expiring", "fee_consent_renewal", "implemented_terms_differ", "catalog_stale", "approval_ageing", "review_required_flag"]
Severity = Literal["readvice", "confirm", "note"]
CheckKey = Literal["facts_unchanged", "product_still_offered", "pricing_unchanged", "suitability_holds", "serviceability_holds", "needs_still_met", "authority_current", "fee_arrangement_current", "holding_matches_implementation", "disclosures_current"]
CheckStatus = Literal["holds", "changed", "unassessed"]
Outcome = Literal["advice_holds", "adviser_confirms", "client_re_disclosure_required", "readvice_required"]


class AdviceReviewError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise AdviceReviewError(code, message)


def _short(text: str) -> str:
    return text if len(text) <= 300 else text[:297] + "..."


def _when(value: Any, *, label: str = "date") -> datetime | None:
    """A timestamp or a date as a datetime; a date-only string ends its day. None and the empty string mean no date; anything else that does not parse is refused rather than dropped."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    _require(isinstance(value, str), "REVIEW_BAD_DATE", f"{label} must be an ISO-8601 date or UTC timestamp, not {type(value).__name__}")
    text = value.strip()
    if "T" not in text:
        text = f"{text}T23:59:59Z"
    try:
        return parsed(timestamp(text, field_name=label))
    except ValueError as exc:
        raise AdviceReviewError("REVIEW_BAD_DATE", f"{label} {value!r} is not an ISO-8601 date or UTC timestamp; a dated obligation is never silently dropped") from exc


def _decimal_or_none(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() else None


def _plan_holders(plan: AdvicePlan | None, vertical_id: str) -> set[tuple[str, str]]:
    """The (kind, holder_ref) pairs the plan holds for the vertical; a verification receipt for any other authority does not speak for this advice."""
    if plan is None:
        return set()
    return {(str(item.kind), str(item.holder_ref)) for item in plan.authorities if not vertical_id or vertical_id in item.scope_verticals}


def _receipt_holder(item: Mapping[str, Any]) -> tuple[str, str]:
    return (str(item.get("authority_kind") or item.get("kind") or ""), str(item.get("holder_ref") or ""))


def _norm(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float, Decimal, str)):
        try:
            return format(Decimal(str(value).replace(",", "").strip()).normalize(), "f")
        except (InvalidOperation, ValueError):
            return str(value).strip().lower() if isinstance(value, str) else value
    if isinstance(value, (list, tuple)):
        return [_norm(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _norm(item) for key, item in sorted(value.items())}
    return value


def _refuse_identity(value: Any, *, label: str) -> None:
    if isinstance(value, Mapping):
        bad = sorted(str(key) for key in value if str(key).lower() in FORBIDDEN_REVIEW_KEYS)
        if bad:
            raise AdviceReviewError("REVIEW_CARRIES_IDENTITY", f"{label} carries {', '.join(bad)}; a review reads decision facts, digests and opaque refs only")
        for item in value.values():
            _refuse_identity(item, label=label)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _refuse_identity(item, label=label)


def _mapping(value: Any, *, label: str) -> dict[str, Any]:
    out = dict(detached(value)) if value is not None else {}
    _refuse_identity(out, label=label)
    return out


def _state(value: ClientState | Mapping[str, Any]) -> ClientState:
    return value if isinstance(value, ClientState) else ClientState.model_validate(dict(detached(value)))


def _plan(value: AdvicePlan | Mapping[str, Any]) -> AdvicePlan:
    return value if isinstance(value, AdvicePlan) else AdvicePlan.model_validate(dict(detached(value)))


def _record(value: RecordOfAdviceEvidence | Mapping[str, Any]) -> RecordOfAdviceEvidence:
    return value if isinstance(value, RecordOfAdviceEvidence) else RecordOfAdviceEvidence.model_validate(dict(detached(value)))


def _catalog(value: ProductCatalog | Mapping[str, Any]) -> ProductCatalog:
    return value if isinstance(value, ProductCatalog) else ProductCatalog.model_validate(dict(detached(value)))


def _find(catalog: ProductCatalog, product_ref: str | None) -> Product | None:
    return next((item for item in catalog.products if item.product_ref == product_ref), None)


def _decision_view(state: ClientState) -> dict[str, Any]:
    """The decision facts as plain data: the structured fields and the fact find, never the commitment or the digest."""
    raw = state.to_dict()
    out: dict[str, Any] = {}
    for key in _STATE_FIELDS:
        value = raw.get(key)
        if value in (None, "", "unstated", [], ()):
            continue
        out[key] = value
    for key, value in sorted((raw.get("facts") or {}).items()):
        if value is None or value == "":
            continue
        out[f"facts.{key}" if key in out else key] = value
    return out


# --------------------------------------------------------------------------- #
# The state diff
# --------------------------------------------------------------------------- #


class FieldChange(StrictModel):
    field: str = Field(min_length=1)
    previous: Any = None
    current: Any = None
    ranked_field: bool


class StateDiff(StrictModel):
    """What the client's disclosed decision facts did between two states of the same client."""

    schema_id: str = Field(default=STATE_DIFF_SCHEMA, alias="schema")
    client_ref: OpaqueRef
    personal_data_sha256: Sha256Digest
    previous_state_digest: Sha256Digest
    current_state_digest: Sha256Digest
    previous_disclosed_at: str
    current_disclosed_at: str
    changed: tuple[FieldChange, ...] = Field(default_factory=tuple)
    added: tuple[str, ...] = Field(default_factory=tuple)
    removed: tuple[str, ...] = Field(default_factory=tuple)
    ranked_fields_changed: tuple[str, ...] = Field(default_factory=tuple)
    life_events: tuple[str, ...] = Field(default_factory=tuple)
    material: bool
    diff_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("changed", "added", "removed", "ranked_fields_changed", "life_events", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> StateDiff:
        if not skip_digests(info) and self.diff_digest != sealed_digest(StateDiff, self, "diff_digest"):
            raise ValueError("diff_digest does not match the diff")
        return self

    @property
    def unchanged(self) -> bool:
        return not (self.changed or self.added or self.removed)

    def fields_touched(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([*(item.field for item in self.changed), *self.added, *self.removed]))


def state_diff(previous: ClientState | Mapping[str, Any], current: ClientState | Mapping[str, Any]) -> StateDiff:
    """Every decision fact that changed, appeared or disappeared between two states of one client, with the ranked fields and the life events the changes signal."""
    before, after = _state(previous), _state(current)
    _require(before.client_ref == after.client_ref and before.personal_data_sha256 == after.personal_data_sha256, "STATE_CLIENT_MISMATCH", "a state diff compares two states of the same client: the client ref and the personal-data commitment must agree")
    _require(before.vertical_id == after.vertical_id, "STATE_VERTICAL_MISMATCH", f"a state diff compares two states disclosed for the same vertical; these are {before.vertical_id} and {after.vertical_id}")
    a, b = _decision_view(before), _decision_view(after)
    changed = [FieldChange(field=key, previous=a[key], current=b[key], ranked_field=key in RANKED_FIELDS) for key in sorted(a) if key in b and _norm(a[key]) != _norm(b[key])]
    added = sorted(key for key in b if key not in a)
    removed = sorted(key for key in a if key not in b)
    touched = [*(item.field for item in changed), *added, *removed]
    ranked = sorted(key for key in touched if key in RANKED_FIELDS)
    signalled = {event for key in touched for event in _FIELD_SIGNALS.get(key, ())}
    events = [event for event in LIFE_EVENTS if event in signalled]
    return seal(StateDiff, {"client_ref": before.client_ref, "personal_data_sha256": before.personal_data_sha256, "previous_state_digest": before.state_digest, "current_state_digest": after.state_digest, "previous_disclosed_at": before.disclosed_at, "current_disclosed_at": after.disclosed_at, "changed": [item.to_dict() for item in changed], "added": added, "removed": removed, "ranked_fields_changed": ranked, "life_events": events, "material": bool(ranked)}, "diff_digest")


def life_event_questions(event: str, vertical_id: str, *, registry: VerticalRegistry | None = None) -> tuple[str, ...]:
    """The facts a life event re-asks, scoped to the ones the vertical's fact find names; the whole row when the fact find names none of them."""
    _require(event in LIFE_EVENTS, "LIFE_EVENT_UNKNOWN", f"{event!r} is not a life event the table knows: {', '.join(LIFE_EVENTS)}")
    requirements = fact_find_requirements(vertical_id, registry=registry)
    asked = {*requirements.required, *requirements.recommended}
    row = LIFE_EVENTS[event]
    return tuple(fact for fact in row if fact in asked) or row


# --------------------------------------------------------------------------- #
# Triggers, checks and the assessment
# --------------------------------------------------------------------------- #


class ReviewTrigger(StrictModel):
    kind: TriggerKind
    due_at: str
    reason: ShortText
    refs: tuple[str, ...] = Field(default_factory=tuple)
    severity: Severity

    @field_validator("refs", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ReviewCheck(StrictModel):
    key: CheckKey
    label: ShortText
    status: CheckStatus
    evidence: tuple[str, ...] = Field(default_factory=tuple)
    detail: ShortText | None = None

    @field_validator("evidence", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ReviewAssessment(StrictModel):
    """One review of one case at one moment: the diff, the triggers, the checks and the outcome, sealed against the record and the states."""

    schema_id: str = Field(default=REVIEW_SCHEMA, alias="schema")
    case_ref: OpaqueRef
    vertical_id: str
    jurisdiction: str
    recommendation_digest: Sha256Digest
    record_digest: Sha256Digest
    implemented_product_ref: OpaqueRef | None = None
    state_digest_at_advice: Sha256Digest
    state_digest_now: Sha256Digest
    diff: StateDiff
    triggers: tuple[ReviewTrigger, ...] = Field(default_factory=tuple)
    checks: tuple[ReviewCheck, ...] = Field(default_factory=tuple)
    outcome: Outcome
    next_review_due_at: str
    disclaimer: str = "A review of whether advice already given still rests on what it rested on; the licensed adviser decides what follows. Advice already given is never rewritten here."
    as_of: str
    assessment_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("triggers", "checks", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ReviewAssessment:
        if not skip_digests(info) and self.assessment_digest != sealed_digest(ReviewAssessment, self, "assessment_digest"):
            raise ValueError("assessment_digest does not match the assessment")
        return self

    def check(self, key: str) -> ReviewCheck | None:
        return next((item for item in self.checks if item.key == key), None)

    def triggered(self, kind: str) -> tuple[ReviewTrigger, ...]:
        return tuple(item for item in self.triggers if item.kind == kind)


def _trigger(kind: str, due_at: str, reason: str, refs: Sequence[str], severity: str) -> ReviewTrigger:
    return ReviewTrigger(kind=kind, due_at=due_at, reason=_short(reason), refs=tuple(refs), severity=severity)  # type: ignore[arg-type]


def _check(key: str, label: str, status: str, evidence: Sequence[str], detail: str | None = None) -> ReviewCheck:
    return ReviewCheck(key=key, label=label, status=status, evidence=tuple(evidence), detail=_short(detail) if detail else None)  # type: ignore[arg-type]


def _values_by_item(pairs: Sequence[tuple[str, Any]]) -> dict[str, tuple[str, ...]]:
    out: dict[str, list[str]] = {}
    for item, value in pairs:
        if value is not None:
            out.setdefault(item.strip().lower(), []).append(str(_norm(value)))
    return {key: tuple(sorted(values)) for key, values in out.items()}


def _pricing_delta(evidence: ProductEvidence, product: Product) -> tuple[list[tuple[str, tuple[str, ...], tuple[str, ...]]], list[str]]:
    """The cited pricing items whose stated values differ in the catalog now, and the ones the catalog no longer states."""
    then = _values_by_item([(fact.item, fact.value) for fact in evidence.facts])
    now = _values_by_item([(fact.item, fact.value) for fact in product.pricing])
    changed = [(item, then[item], now[item]) for item in then if item in now and then[item] != now[item]]
    removed = [item for item in then if item not in now]
    return changed, removed


def _pending_impact(item: Mapping[str, Any]) -> bool:
    status = str(item.get("status") or "").strip().lower()
    if status and status not in ("pending", "open", "unresolved"):
        return False
    if item.get("resolved_at") or item.get("dismissed_at"):
        return False
    return item.get("recompute", True) is not False


def _impact_ref(item: Mapping[str, Any]) -> str:
    return str(item.get("impact_ref") or item.get("event_ref") or item.get("impact_id") or item.get("id") or "unnamed")


def _quote_expiry(item: Mapping[str, Any]) -> datetime | None:
    expiry = _when(item.get("valid_until"))
    if expiry is not None:
        return expiry
    quoted = _when(item.get("quoted_at"))
    return quoted + timedelta(days=QUOTE_VALIDITY_DAYS) if quoted is not None else None


def _authority_expiry(item: Mapping[str, Any]) -> datetime | None:
    return _when(item.get("expires_on")) or _when(item.get("expires_at"))


def _authority_label(item: Mapping[str, Any]) -> str:
    return f"{item.get('authority_kind') or item.get('kind') or 'authority'} ({item.get('holder_ref') or 'holder unstated'})"


def review_triggers(case_summary: Mapping[str, Any], *, state_at_advice: ClientState | Mapping[str, Any] | None, state_now: ClientState | Mapping[str, Any] | None, record: RecordOfAdviceEvidence | Mapping[str, Any] | None, catalog_now: ProductCatalog | Mapping[str, Any] | None, quotes: Sequence[Mapping[str, Any]] = (), fee_arrangements: Sequence[Mapping[str, Any]] = (), verifications: Sequence[Mapping[str, Any]] = (), impacts: Sequence[Mapping[str, Any]] = (), reconciliation: Mapping[str, Any] | None = None, life_events: Sequence[str] = (), plan: AdvicePlan | Mapping[str, Any] | None = None, as_of: str) -> tuple[ReviewTrigger, ...]:
    """Every dated reason this case is due for attention at ``as_of``, each with its severity; the highest severity first."""
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    summary = _mapping(case_summary, label="case_summary")
    rec = _record(record) if record is not None else None
    p = _plan(plan) if plan is not None else None
    case_ref = str(summary.get("case_ref") or "case")
    vertical_id = str(summary.get("vertical_id") or (rec.vertical_id if rec else ""))
    product_ref = summary.get("implemented_product_ref") or summary.get("primary_product_ref") or (rec.recommended.product_ref if rec is not None and rec.recommended is not None else None)
    out: list[ReviewTrigger] = []

    due = _when(summary.get("review_due_at"))
    if due is not None and due <= now:
        out.append(_trigger("review_due", iso(due), f"the review the case set for {iso(due)[:10]} is due", [f"case:{case_ref}"], "confirm"))
    if summary.get("review_required"):
        changes = [str(item) for item in (summary.get("fact_changes") or ())]
        reason = str(summary.get("review_required_reason") or (changes[-1] if changes else "a published fact change reached the case after the adviser's approval"))
        out.append(_trigger("review_required_flag", stamp, f"the case is flagged for the adviser's review: {reason}", [f"case:{case_ref}", *(f"fact_change:{index}" for index in range(len(changes)))], "confirm"))

    if state_at_advice is not None and state_now is not None:
        diff = state_diff(state_at_advice, state_now)
        if diff.ranked_fields_changed:
            signalled = f"; signals {', '.join(diff.life_events)}" if diff.life_events else ""
            out.append(_trigger("fact_changed", diff.current_disclosed_at, "ranked decision facts changed since the advice: " + ", ".join(diff.ranked_fields_changed) + signalled, [f"diff:{diff.diff_digest}", *(f"fact:{field}" for field in diff.ranked_fields_changed)], "readvice"))
        elif not diff.unchanged:
            out.append(_trigger("fact_changed", diff.current_disclosed_at, "decision facts changed since the advice, none of them ranked: " + ", ".join(diff.fields_touched()), [f"diff:{diff.diff_digest}", *(f"fact:{field}" for field in diff.fields_touched())], "note"))

    for event in life_events:
        questions = life_event_questions(str(event), vertical_id) if vertical_id else LIFE_EVENTS.get(str(event)) or ()
        _require(str(event) in LIFE_EVENTS, "LIFE_EVENT_UNKNOWN", f"{event!r} is not a life event the table knows")
        out.append(_trigger("life_event", stamp, f"{event}: the client re-discloses " + ", ".join(questions), [f"life_event:{event}", *(f"fact:{fact}" for fact in questions)], "confirm"))

    if rec is not None and rec.recommended is not None and catalog_now is not None:
        c = _catalog(catalog_now)
        run_date = c.run_date if "T" in c.run_date else f"{c.run_date}T00:00:00Z"
        age_days = (now - parsed(run_date)).days
        stale = p is not None and age_days > p.max_catalog_age_days
        if stale:
            out.append(_trigger("catalog_stale", stamp, f"the published catalog is {age_days} days old at the review; the plan allows {p.max_catalog_age_days}; product facts cannot be rechecked against it", [f"catalog:{c.catalog_digest}"], "note"))
        product = _find(c, rec.recommended.product_ref)
        if product is None or (product.availability_status or "").strip().lower() in _WITHDRAWN:
            out.append(_trigger("product_withdrawn", stamp, f"{rec.recommended.product_name} by {rec.recommended.provider_name} is " + ("no longer in the published catalog" if product is None else f"stated {product.availability_status}"), [f"record:{rec.record_digest}", f"catalog:{c.catalog_digest}", f"product:{rec.recommended.product_ref}"], "readvice"))
        elif not stale:
            changed, removed = _pricing_delta(rec.recommended, product)
            if changed:
                out.append(_trigger("product_fact_changed", stamp, "cited facts of the recommended product changed in the published catalog: " + "; ".join(f"{item} {'/'.join(then)} is now {'/'.join(after)}" for item, then, after in changed), [f"record:{rec.record_digest}", f"catalog:{c.catalog_digest}", *(f"fact:{rec.recommended.product_ref}#{item}" for item, _, _ in changed)], "readvice"))
            elif removed:
                out.append(_trigger("product_fact_changed", stamp, "the published catalog no longer states cited facts of the recommended product: " + ", ".join(removed), [f"record:{rec.record_digest}", f"catalog:{c.catalog_digest}", *(f"fact:{rec.recommended.product_ref}#{item}" for item in removed)], "confirm"))

    for item in impacts:
        m = _mapping(item, label="impact")
        if not _pending_impact(m):
            continue
        impact_case = m.get("case_ref") or m.get("entity_ref")
        if impact_case and str(impact_case) != case_ref:
            continue
        due_at = _when(m.get("occurred_at")) or _when(m.get("created_at")) or now
        refs = [f"impact:{_impact_ref(m)}", *(f"product:{ref}" for ref in (m.get("changed_product_refs") or m.get("affected_product_refs") or ()))]
        out.append(_trigger("product_fact_changed", iso(due_at), f"a fact change reached the case and is not resolved: {m.get('reason') or m.get('event_ref') or _impact_ref(m)}", refs, "confirm"))

    for item in quotes:
        m = _mapping(item, label="quote")
        if product_ref and m.get("product_ref") not in (None, product_ref):
            continue
        expiry = _quote_expiry(m)
        if expiry is not None and expiry <= now:
            out.append(_trigger("quote_expired", iso(expiry), f"the quote the pricing rested on expired on {iso(expiry)[:10]}" + (f" (profile {m.get('profile_ref')})" if m.get("profile_ref") else ""), [f"quote:{m.get('product_ref') or product_ref or 'unnamed'}", *( [f"profile:{m['profile_ref']}"] if m.get("profile_ref") else [])], "confirm"))

    seen_authorities: set[str] = set()
    holders = _plan_holders(p, vertical_id)
    for item in verifications:
        m = _mapping(item, label="verification")
        if holders and _receipt_holder(m) not in holders:
            continue
        expiry = _authority_expiry(m)
        label = _authority_label(m)
        if expiry is not None and expiry <= now + timedelta(days=AUTHORITY_EXPIRING_DAYS) and label not in seen_authorities:
            seen_authorities.add(label)
            out.append(_trigger("authority_expiring", iso(expiry), f"the register gives an expiry of {iso(expiry)[:10]} for {label}" + (" (already past)" if expiry <= now else ""), [f"verification:{m.get('verification_digest') or 'unsealed'}"], "confirm"))
    if p is not None:
        for authority in p.authorities:
            if vertical_id and vertical_id not in authority.scope_verticals:
                continue
            expiry = _when(authority.expires_at)
            label = f"{authority.kind} ({authority.holder_ref})"
            if expiry is not None and expiry <= now + timedelta(days=AUTHORITY_EXPIRING_DAYS) and label not in seen_authorities:
                seen_authorities.add(label)
                out.append(_trigger("authority_expiring", iso(expiry), f"the plan's own expiry for {label} is {iso(expiry)[:10]}" + (" (already past)" if expiry <= now else ""), [f"plan:{p.plan_digest}", f"authority:{authority.holder_ref}"], "confirm"))

    for item in fee_arrangements:
        m = _mapping(item, label="fee_arrangement")
        renewal = _when(m.get("renewal_due_at"))
        if renewal is not None and renewal <= now + timedelta(days=FEE_RENEWAL_WINDOW_DAYS):
            out.append(_trigger("fee_consent_renewal", iso(renewal), f"the ongoing fee consent for {m.get('arrangement_ref') or 'the arrangement'} is due for renewal on {iso(renewal)[:10]}" + (" (already past)" if renewal <= now else ""), [f"fee_arrangement:{m.get('arrangement_ref') or 'unnamed'}", *( [f"arrangement:{m['arrangement_digest']}"] if m.get("arrangement_digest") else [])], "confirm"))

    if reconciliation is not None:
        m = _mapping(reconciliation, label="reconciliation")
        if str(m.get("verdict") or "") == "differs":
            severity = "readvice" if m.get("readvice_required") else ("confirm" if m.get("material", True) else "note")
            differences = [str(d.get("item")) for d in (m.get("differences") or ()) if isinstance(d, Mapping)]
            out.append(_trigger("implemented_terms_differ", stamp, "the implemented terms differ from the cited terms the recommendation rested on: " + (", ".join(differences) or "see the reconciliation"), [f"reconciliation:{m.get('reconciliation_digest') or 'unsealed'}", *(f"term:{item}" for item in differences)], severity))

    if str(summary.get("status") or "") == "adviser_approved":
        approved = _when(summary.get("approved_at")) or (_when((rec.approval or {}).get("approved_at")) if rec is not None else None)
        if approved is not None and now - approved > timedelta(days=APPROVAL_AGEING_DAYS):
            out.append(_trigger("approval_ageing", iso(approved + timedelta(days=APPROVAL_AGEING_DAYS)), f"the adviser approved on {iso(approved)[:10]} and nothing was presented within {APPROVAL_AGEING_DAYS} days; the pricing and the approval may no longer stand", [f"case:{case_ref}", f"approval:{(rec.approval or {}).get('approval_ref') if rec is not None else 'unstated'}"], "confirm"))

    out.sort(key=lambda item: (-_SEVERITY_RANK[item.severity], item.due_at, item.kind))
    return tuple(out)


def _verification_covering(verifications: Sequence[Mapping[str, Any]], *, vertical_id: str, family: str, now: datetime, plan: AdvicePlan) -> tuple[dict[str, Any] | None, list[dict[str, Any]], int]:
    """The verified receipt for an authority the plan holds for this vertical's family that is fresh at ``now``, every receipt considered (freshest first), and how many receipts for other authorities were ignored."""
    holders = _plan_holders(plan, vertical_id)
    considered: list[dict[str, Any]] = []
    ignored = 0
    for item in verifications:
        m = _mapping(item, label="verification")
        if m.get("vertical_id") not in (None, vertical_id) or m.get("family") not in (None, family):
            continue
        if holders and _receipt_holder(m) not in holders:
            ignored += 1
            continue
        considered.append(m)
    considered.sort(key=lambda m: str(m.get("verified_at") or ""), reverse=True)
    for m in considered:
        verified_at = _when(m.get("verified_at"), label="verified_at")
        expiry = _authority_expiry(m)
        fresh = verified_at is not None and now - verified_at <= timedelta(days=VERIFICATION_MAX_AGE_DAYS) and verified_at <= now
        if m.get("verdict") == "verified" and fresh and (expiry is None or expiry > now):
            return m, considered, ignored
    return None, considered, ignored


def _checks(*, rec: RecordOfAdviceEvidence, after: ClientState, catalog: ProductCatalog, plan: AdvicePlan, diff: StateDiff, summary: Mapping[str, Any], needs_now: Mapping[str, Any] | None, serviceability_now: Mapping[str, Any] | None, engagement: Mapping[str, Any] | None, verifications: Sequence[Mapping[str, Any]], reconciliation: Mapping[str, Any] | None, now: datetime, stamp: str) -> tuple[list[ReviewCheck], list[ReviewTrigger]]:
    assert rec.recommended is not None
    evidence = rec.recommended
    ref = evidence.product_ref
    checks: list[ReviewCheck] = []
    extra: list[ReviewTrigger] = []
    diff_ref = f"diff:{diff.diff_digest}"

    if diff.unchanged:
        checks.append(_check("facts_unchanged", "The decision facts the advice rested on are unchanged", "holds", [diff_ref, f"state:{after.state_digest}"]))
    else:
        checks.append(_check("facts_unchanged", "The decision facts the advice rested on are unchanged", "changed", [diff_ref, f"state:{after.state_digest}"], "changed: " + ", ".join(diff.fields_touched()) + (f"; ranked: {', '.join(diff.ranked_fields_changed)}" if diff.ranked_fields_changed else "; none ranked")))

    product = _find(catalog, ref)
    catalog_ref = f"catalog:{catalog.catalog_digest}"
    run_date = catalog.run_date if "T" in catalog.run_date else f"{catalog.run_date}T00:00:00Z"
    age_days = (now - parsed(run_date)).days
    stale = age_days > plan.max_catalog_age_days
    offered = product is not None and (product.availability_status or "").strip().lower() not in _WITHDRAWN
    checks.append(_check("product_still_offered", "The recommended product is still in the published catalog", "holds" if offered else "changed", [catalog_ref, f"product:{ref}"], None if offered else ("the product is not in the published catalog" if product is None else f"the catalog states {product.availability_status}")))

    if product is None:
        checks.append(_check("pricing_unchanged", "The cited pricing facts of the recommended product still hold", "unassessed", [catalog_ref, f"record:{rec.record_digest}"], "the product is not in the published catalog; nothing to compare"))
    elif stale:
        checks.append(_check("pricing_unchanged", "The cited pricing facts of the recommended product still hold", "unassessed", [catalog_ref, f"record:{rec.record_digest}"], f"the catalog is {age_days} days old; the plan allows {plan.max_catalog_age_days}"))
    else:
        changed, removed = _pricing_delta(evidence, product)
        if changed or removed:
            detail = "; ".join(f"{item} {'/'.join(then)} is now {'/'.join(after_values)}" for item, then, after_values in changed) + (("; no longer stated: " + ", ".join(removed)) if removed else "")
            checks.append(_check("pricing_unchanged", "The cited pricing facts of the recommended product still hold", "changed", [catalog_ref, f"record:{rec.record_digest}", *(f"fact:{ref}#{item}" for item, _, _ in changed), *(f"fact:{ref}#{item}" for item in removed)], detail))
        else:
            checks.append(_check("pricing_unchanged", "The cited pricing facts of the recommended product still hold", "holds", [catalog_ref, f"record:{rec.record_digest}"], f"{len(evidence.facts)} cited fact(s) state the same values"))

    if product is None:
        checks.append(_check("suitability_holds", "Suitability re-evaluated against the current state", "unassessed", [f"state:{after.state_digest}"], "the product is not in the published catalog"))
    else:
        verdict = evaluate_suitability(product, after)
        reasons = "; ".join(verdict.reasons)
        if verdict.outcome == "ineligible":
            checks.append(_check("suitability_holds", "Suitability re-evaluated against the current state", "changed", [f"state:{after.state_digest}", f"fact:{ref}#suitability"], f"now ineligible (was {evidence.suitability}): {reasons}"))
            kind = "fact_changed" if not diff.unchanged else "product_fact_changed"
            extra.append(_trigger(kind, stamp, f"the recommended product is now ineligible for the client: {reasons}", [diff_ref, f"suitability:{ref}"], "readvice"))
        elif verdict.outcome == "unassessed" and evidence.suitability == "eligible":
            checks.append(_check("suitability_holds", "Suitability re-evaluated against the current state", "unassessed", [f"state:{after.state_digest}", f"fact:{ref}#suitability"], f"a restriction is no longer settled by the fact find: {', '.join(verdict.unconfirmed) or reasons}"))
        else:
            checks.append(_check("suitability_holds", "Suitability re-evaluated against the current state", "holds", [f"state:{after.state_digest}", f"fact:{ref}#suitability"], f"{verdict.outcome}: {reasons}"))

    if rec.family == "credit":
        if serviceability_now is None:
            checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "unassessed", [f"state:{after.state_digest}"], "no serviceability verdict was passed for the current state; the strategy work computes it"))
        else:
            m = _mapping(serviceability_now, label="serviceability")
            s_ref = f"serviceability:{m.get('serviceability_digest') or 'unsealed'}"
            verdict_now = str(m.get("verdict") or "unassessed")
            if m.get("state_digest") not in (None, after.state_digest):
                checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "unassessed", [s_ref], "the serviceability verdict was prepared for another state; recompute it for the current one"))
            elif m.get("product_ref") not in (None, ref):
                checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "unassessed", [s_ref], "the serviceability verdict is for another product"))
            elif verdict_now == "serviceable":
                checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "holds", [s_ref, f"state:{after.state_digest}"], "; ".join(str(item) for item in (m.get("reasons") or ())) or "serviceable"))
            elif verdict_now == "not_serviceable":
                checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "changed", [s_ref, f"state:{after.state_digest}"], "; ".join(str(item) for item in (m.get("reasons") or ())) or "not serviceable at the buffered rate"))
                extra.append(_trigger("fact_changed", stamp, "the client no longer services the recommended product at the buffered rate", [s_ref, diff_ref], "readvice"))
            else:
                checks.append(_check("serviceability_holds", "Serviceability verdict for the current state", "unassessed", [s_ref], "; ".join(str(item) for item in (m.get("missing") or ())) or "the verdict is unassessed"))

    if needs_kind(rec.vertical_id) in _NEEDS_KINDS:
        assessment = assess_needs(after)
        then_stated = (rec.needs or {}).get("need")
        then_need = _decimal_or_none(then_stated)
        fit = _mapping(needs_now, label="needs") if needs_now is not None else {}
        fit_need = _decimal_or_none(fit.get("need"))
        refs = [f"state:{after.state_digest}", f"record:{rec.record_digest}"]
        if fit and fit.get("product_ref") not in (None, ref):
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "unassessed", refs, f"the benefit fit is for {fit.get('product_ref')}, not the recommended {ref}; recompute it for the recommended product"))
        elif fit and assessment.need is not None and fit_need is not None and fit_need != assessment.need:
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "unassessed", refs, f"the benefit fit was computed for a need of {fit_need}; the current facts call for {assessment.need} {assessment.unit}; recompute it for the current state"))
        elif fit.get("fit") in ("meets", "exceeds"):
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "holds", refs, f"benefit fit {fit['fit']}: need {fit.get('need')} against benefit {fit.get('benefit')}"))
        elif fit.get("fit") == "short":
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "changed", refs, f"benefit fit short by {fit.get('shortfall')} against a need of {fit.get('need')}"))
            extra.append(_trigger("fact_changed", stamp, f"the implemented cover is short of the need the current facts call for by {fit.get('shortfall')}", [diff_ref, f"needs:{assessment.kind}"], "readvice"))
        elif assessment.need is None:
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "unassessed", refs, "the current facts do not state " + ", ".join(assessment.missing)))
        elif then_need is None:
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "unassessed", refs, ("the record carries no assessed need to compare" if then_stated is None else f"the record's assessed need {then_stated!r} is not a number") + f"; the need now is {assessment.need} {assessment.unit}"))
        elif assessment.need > then_need:
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "changed", refs, f"the need rose from {then_need} to {assessment.need} {assessment.unit}"))
        else:
            checks.append(_check("needs_still_met", "The cover still meets the need the current facts call for", "holds", refs, f"the need is {assessment.need} {assessment.unit}, not above the {then_need} the advice rested on"))

    covering, considered, ignored = _verification_covering(verifications, vertical_id=rec.vertical_id, family=rec.family, now=now, plan=plan)
    if covering is not None:
        checks.append(_check("authority_current", "The authority the advice was given under is verified and current", "holds", [f"verification:{covering.get('verification_digest') or 'unsealed'}"], f"verified against {covering.get('register_name')} on {str(covering.get('verified_at'))[:10]}"))
    elif considered:
        latest = considered[0]
        checks.append(_check("authority_current", "The authority the advice was given under is verified and current", "changed", [f"verification:{m.get('verification_digest') or 'unsealed'}" for m in considered], f"the latest receipt is {latest.get('verdict')} ({', '.join(str(f) for f in (latest.get('findings') or ())) or 'no finding'}) read on {str(latest.get('verified_at'))[:10]}; a verified receipt within {VERIFICATION_MAX_AGE_DAYS} days is needed"))
    else:
        checks.append(_check("authority_current", "The authority the advice was given under is verified and current", "unassessed", [f"plan:{plan.plan_digest}"], "no verification receipt was given for the authority the plan holds for this vertical" + (f"; {ignored} receipt(s) for other authorities ignored" if ignored else "")))

    eng = _mapping(engagement, label="engagement") if engagement is not None else None
    fee = dict(eng.get("fee_arrangement") or {}) if eng is not None else {}
    if fee:
        fee_ref = f"fee_arrangement:{fee.get('arrangement_ref') or 'unnamed'}"
        renewal = _when(fee.get("renewal_due_at"))
        if fee.get("kind") == "one_off":
            checks.append(_check("fee_arrangement_current", "The fee arrangement is current", "holds", [fee_ref], "a one-off fee arrangement has no renewal"))
        elif renewal is None:
            checks.append(_check("fee_arrangement_current", "The fee arrangement is current", "unassessed", [fee_ref], "the ongoing arrangement states no renewal date"))
        elif renewal > now:
            checks.append(_check("fee_arrangement_current", "The fee arrangement is current", "holds", [fee_ref], f"renewal due {iso(renewal)[:10]}"))
        else:
            checks.append(_check("fee_arrangement_current", "The fee arrangement is current", "changed", [fee_ref], f"the renewal fell due on {iso(renewal)[:10]} and no renewed consent is on the engagement"))

    implemented = summary.get("implemented_product_ref")
    if implemented or str(summary.get("status") or "") in ("implemented", "reviewed"):
        refs = [f"case:{summary.get('case_ref') or 'case'}", f"record:{rec.record_digest}"]
        if implemented and implemented != ref:
            checks.append(_check("holding_matches_implementation", "What was implemented is what was recommended", "changed", refs, f"the case implemented {implemented}; the record recommends {ref}"))
        elif reconciliation is not None:
            m = _mapping(reconciliation, label="reconciliation")
            r_ref = f"reconciliation:{m.get('reconciliation_digest') or 'unsealed'}"
            verdict = str(m.get("verdict") or "unassessed")
            if verdict == "as_recommended":
                checks.append(_check("holding_matches_implementation", "What was implemented is what was recommended", "holds", [*refs, r_ref], f"{m.get('compared') or 0} term(s) reconciled as recommended"))
            elif verdict == "differs":
                checks.append(_check("holding_matches_implementation", "What was implemented is what was recommended", "changed", [*refs, r_ref], "implemented terms differ: " + ", ".join(str(d.get("item")) for d in (m.get("differences") or ()) if isinstance(d, Mapping))))
            else:
                checks.append(_check("holding_matches_implementation", "What was implemented is what was recommended", "unassessed", [*refs, r_ref], "the reconciliation is unassessed"))
        else:
            checks.append(_check("holding_matches_implementation", "What was implemented is what was recommended", "holds", refs, "the implemented product ref is the recommended one; no terms reconciliation was passed"))

    needed = _PRESENTATION_DISCLOSURES.get((rec.jurisdiction, rec.family), ())
    if eng is None:
        if needed:
            checks.append(_check("disclosures_current", "The disclosures the presentation required were given", "unassessed", [f"record:{rec.record_digest}"], "no engagement pack was given; " + ", ".join(needed) + " must have been given before the presentation"))
        else:
            checks.append(_check("disclosures_current", "The disclosures the presentation required were given", "holds", [f"record:{rec.record_digest}"], f"no presentation-stage disclosure is required for {rec.jurisdiction} {rec.family}; the record carries {len(rec.disclosures)} disclosure(s)"))
    else:
        given = {str(item.get("kind")) for item in (eng.get("given") or ()) if isinstance(item, Mapping)}
        missing = [kind for kind in needed if kind not in given]
        e_ref = f"engagement:{eng.get('engagement_digest') or 'unsealed'}"
        if missing:
            checks.append(_check("disclosures_current", "The disclosures the presentation required were given", "changed", [e_ref], "not given: " + ", ".join(missing)))
        elif eng.get("complete") is False:
            checks.append(_check("disclosures_current", "The disclosures the presentation required were given", "changed", [e_ref], "the engagement pack is incomplete: " + ", ".join(str(item) for item in (eng.get("missing") or ()))))
        else:
            checks.append(_check("disclosures_current", "The disclosures the presentation required were given", "holds", [e_ref], f"{len(given)} disclosure kind(s) given" + (f", including {', '.join(needed)}" if needed else "")))
    return checks, extra


def _outcome(triggers: Sequence[ReviewTrigger], checks: Sequence[ReviewCheck]) -> str:
    """The highest severity across triggers and checks: re-advice, then re-disclosure, then the adviser's confirmation, else the advice holds."""
    if any(item.severity == "readvice" for item in triggers):
        return "readvice_required"
    if any(item.kind == "life_event" for item in triggers):
        return "client_re_disclosure_required"
    if any(item.severity == "confirm" for item in triggers) or any(item.status != "holds" for item in checks):
        return "adviser_confirms"
    return "advice_holds"


def review_assessment(plan: AdvicePlan | Mapping[str, Any], case_summary: Mapping[str, Any], record: RecordOfAdviceEvidence | Mapping[str, Any], *, state_at_advice: ClientState | Mapping[str, Any], state_now: ClientState | Mapping[str, Any], catalog_now: ProductCatalog | Mapping[str, Any], needs_now: Mapping[str, Any] | None = None, serviceability_now: Mapping[str, Any] | None = None, engagement: Mapping[str, Any] | None = None, verifications: Sequence[Mapping[str, Any]] = (), quotes: Sequence[Mapping[str, Any]] = (), impacts: Sequence[Mapping[str, Any]] = (), reconciliation: Mapping[str, Any] | None = None, life_events: Sequence[str] = (), as_of: str) -> ReviewAssessment:
    """One sealed review of one case: the diff, every trigger, every check and the outcome, which is the highest severity found."""
    p = _plan(plan)
    rec = _record(record)
    before, after = _state(state_at_advice), _state(state_now)
    c = _catalog(catalog_now)
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    summary = _mapping(case_summary, label="case_summary")
    _require(rec.recommended is not None and rec.recommendation_digest is not None, "REVIEW_NO_RECOMMENDATION", "a review reads a record that carries a recommendation; nothing was advised")
    _require(rec.plan_digest == p.plan_digest, "REVIEW_PLAN_MISMATCH", "the record was prepared under a different plan")
    _require(rec.state_digest == before.state_digest, "REVIEW_STATE_MISMATCH", "the record was prepared from a different client state than the one given as the state at advice")
    _require(before.vertical_id == rec.vertical_id == after.vertical_id, "REVIEW_VERTICAL_MISMATCH", f"the record is {rec.vertical_id}; the states are {before.vertical_id} and {after.vertical_id}")
    _require(before.jurisdiction == rec.jurisdiction == after.jurisdiction, "REVIEW_JURISDICTION_MISMATCH", f"the record is {rec.jurisdiction} advice; the states are disclosed under {before.jurisdiction} and {after.jurisdiction}; advice is not reviewed across jurisdictions, a successor case is opened")
    _require(c.vertical_id == rec.vertical_id, "REVIEW_CATALOG_MISMATCH", f"the catalog is {c.vertical_id}; the record is {rec.vertical_id}")
    _require(str(summary.get("vertical_id") or rec.vertical_id) == rec.vertical_id, "REVIEW_CASE_MISMATCH", "the case is in another vertical than the record")
    diff = state_diff(before, after)
    eng = _mapping(engagement, label="engagement") if engagement is not None else None
    fees = [eng["fee_arrangement"]] if eng is not None and eng.get("fee_arrangement") else []
    triggers = list(review_triggers(summary, state_at_advice=before, state_now=after, record=rec, catalog_now=c, quotes=quotes, fee_arrangements=fees, verifications=verifications, impacts=impacts, reconciliation=reconciliation, life_events=life_events, plan=p, as_of=stamp))
    checks, extra = _checks(rec=rec, after=after, catalog=c, plan=p, diff=diff, summary=summary, needs_now=needs_now, serviceability_now=serviceability_now, engagement=eng, verifications=verifications, reconciliation=reconciliation, now=now, stamp=stamp)
    triggers.extend(extra)
    triggers.sort(key=lambda item: (-_SEVERITY_RANK[item.severity], item.due_at, item.kind))
    outcome = _outcome(triggers, checks)
    implemented = summary.get("implemented_product_ref")
    assert rec.recommendation_digest is not None
    return seal(ReviewAssessment, {
        "case_ref": str(summary.get("case_ref") or "case"), "vertical_id": rec.vertical_id, "jurisdiction": rec.jurisdiction, "recommendation_digest": rec.recommendation_digest, "record_digest": rec.record_digest,
        "implemented_product_ref": str(implemented) if implemented else None, "state_digest_at_advice": before.state_digest, "state_digest_now": after.state_digest, "diff": diff.to_dict(),
        "triggers": [item.to_dict() for item in triggers], "checks": [item.to_dict() for item in checks], "outcome": outcome,
        "next_review_due_at": add_days(stamp, p.review_after_days) if outcome == "advice_holds" else stamp, "as_of": stamp,
    }, "assessment_digest")


# --------------------------------------------------------------------------- #
# Receipts for the lifecycle
# --------------------------------------------------------------------------- #


def review_receipt(assessment: ReviewAssessment | Mapping[str, Any], *, outcome_note: str | None = None, successor_case_ref: str | None = None) -> dict[str, Any]:
    """The receipt the case's ``review`` transition binds; re-advice needs the successor case that carries the new advice."""
    a = assessment if isinstance(assessment, ReviewAssessment) else ReviewAssessment.model_validate(dict(detached(assessment)))
    _require(a.outcome != "readvice_required" or bool(successor_case_ref), "SUCCESSOR_REQUIRED", "re-advice is a successor case; open it and name its case ref on the review receipt, the advice already given is never rewritten")
    changed = [item.key for item in a.checks if item.status != "holds"]
    summary = outcome_note or (f"{len(a.triggers)} trigger(s), {len(changed)} check(s) not holding" + (f": {', '.join(changed)}" if changed else "") + (f"; {a.triggers[0].reason}" if a.triggers else ""))
    refs = [f"review:{a.assessment_digest}", f"record:{a.record_digest}", f"recommendation:{a.recommendation_digest}", f"diff:{a.diff.diff_digest}"]
    if successor_case_ref:
        refs.append(f"successor:{successor_case_ref}")
    return {"review_outcome": _short(f"{a.outcome}: {summary}"), "review_digest": a.assessment_digest, "successor_case_ref": successor_case_ref, "next_review_due_at": a.next_review_due_at, "evidence_refs": refs[:12]}


def successor_intake_receipt(case_summary: Mapping[str, Any], *, state_now: ClientState | Mapping[str, Any]) -> dict[str, Any]:
    """The intake receipt that opens the successor case: the same client, the predecessor named, and a fact find that must be re-disclosed."""
    summary = _mapping(case_summary, label="case_summary")
    after = _state(state_now)
    vertical_id = str(summary.get("vertical_id") or after.vertical_id)
    _require(after.vertical_id == vertical_id, "SUCCESSOR_VERTICAL_MISMATCH", f"the successor state is {after.vertical_id}; the predecessor case is {vertical_id}")
    _require(bool(summary.get("case_ref")), "PREDECESSOR_UNNAMED", "the predecessor case names its case ref")
    return {"client_ref": after.client_ref, "vertical_id": vertical_id, "objective": after.objective or str(summary.get("objective") or ""), "personal_data_sha256": after.personal_data_sha256, "predecessor_case_ref": str(summary["case_ref"]), "fact_find_complete": False, "evidence_refs": [f"predecessor:{summary['case_ref']}", f"client_state:{after.disclosed_at[:10]}"]}


# --------------------------------------------------------------------------- #
# The calendar
# --------------------------------------------------------------------------- #


class CalendarEntry(StrictModel):
    due_at: str
    kind: TriggerKind
    case_ref: OpaqueRef | None = None
    ref: str = Field(min_length=1)
    reason: ShortText
    overdue: bool


class ReviewCalendar(StrictModel):
    """Everything due across the cases within the horizon, date-ordered, overdue first."""

    schema_id: str = Field(default=CALENDAR_SCHEMA, alias="schema")
    as_of: str
    horizon_days: int = Field(ge=1, le=3650)
    entries: tuple[CalendarEntry, ...] = Field(default_factory=tuple)
    counts: dict[str, int] = Field(default_factory=dict)
    calendar_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("entries", mode="before")
    @classmethod
    def _tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def _seal(self, info: ValidationInfo) -> ReviewCalendar:
        if not skip_digests(info) and self.calendar_digest != sealed_digest(ReviewCalendar, self, "calendar_digest"):
            raise ValueError("calendar_digest does not match the calendar")
        return self


def review_calendar(cases: Sequence[Mapping[str, Any]], *, quotes: Sequence[Mapping[str, Any]] = (), fee_arrangements: Sequence[Mapping[str, Any]] = (), authorities: Sequence[Mapping[str, Any]] = (), impacts: Sequence[Mapping[str, Any]] = (), as_of: str, horizon_days: int = DEFAULT_CALENDAR_HORIZON_DAYS) -> ReviewCalendar:
    """The dated obligations across cases: reviews due, flagged cases, quotes expiring, fee consents renewing, authorities expiring, unresolved impacts."""
    _require(isinstance(horizon_days, int) and not isinstance(horizon_days, bool) and 1 <= horizon_days <= 3650, "CALENDAR_HORIZON_INVALID", f"horizon_days must be a whole number of days from 1 to 3650, not {horizon_days!r}")
    stamp = timestamp(as_of, field_name="as_of")
    now = parsed(stamp)
    limit = now + timedelta(days=horizon_days)
    entries: list[CalendarEntry] = []

    def add(kind: str, due: datetime, *, case_ref: Any, ref: str, reason: str) -> None:
        if due > limit:
            return
        entries.append(CalendarEntry(due_at=iso(due), kind=kind, case_ref=str(case_ref) if case_ref else None, ref=ref, reason=_short(reason), overdue=due < now))  # type: ignore[arg-type]

    by_product: dict[str, str] = {}
    for item in cases:
        m = _mapping(item, label="case_summary")
        case_ref = m.get("case_ref")
        for key in ("implemented_product_ref", "primary_product_ref"):
            if m.get(key) and case_ref:
                by_product.setdefault(str(m[key]), str(case_ref))
        due = _when(m.get("review_due_at"))
        if due is not None:
            add("review_due", due, case_ref=case_ref, ref=f"case:{case_ref or 'unnamed'}", reason=f"review set for {iso(due)[:10]} in {m.get('vertical_id') or 'the case'}")
        if m.get("review_required"):
            add("review_required_flag", now, case_ref=case_ref, ref=f"case:{case_ref or 'unnamed'}", reason=str(m.get("review_required_reason") or "flagged for the adviser's review after a fact change"))
        approved = _when(m.get("approved_at"))
        if str(m.get("status") or "") == "adviser_approved" and approved is not None:
            add("approval_ageing", approved + timedelta(days=APPROVAL_AGEING_DAYS), case_ref=case_ref, ref=f"case:{case_ref or 'unnamed'}", reason=f"approved on {iso(approved)[:10]} and not yet presented")
    for item in quotes:
        m = _mapping(item, label="quote")
        expiry = _quote_expiry(m)
        if expiry is not None:
            product = str(m.get("product_ref") or "unnamed")
            add("quote_expired", expiry, case_ref=by_product.get(product), ref=f"quote:{product}" + (f":{m['profile_ref']}" if m.get("profile_ref") else ""), reason=f"quote for {product} expires {iso(expiry)[:10]}")
    for item in fee_arrangements:
        m = _mapping(item, label="fee_arrangement")
        renewal = _when(m.get("renewal_due_at"))
        if renewal is not None:
            add("fee_consent_renewal", renewal, case_ref=m.get("case_ref"), ref=f"fee_arrangement:{m.get('arrangement_ref') or 'unnamed'}", reason=f"ongoing fee consent renews {iso(renewal)[:10]}")
    for item in authorities:
        m = _mapping(item, label="authority")
        expiry = _authority_expiry(m)
        if expiry is not None:
            add("authority_expiring", expiry, case_ref=None, ref=f"authority:{m.get('holder_ref') or 'unnamed'}:{m.get('authority_kind') or m.get('kind') or 'authority'}", reason=f"{_authority_label(m)} expires {iso(expiry)[:10]}")
    for item in impacts:
        m = _mapping(item, label="impact")
        if not _pending_impact(m):
            continue
        due = _when(m.get("occurred_at")) or _when(m.get("created_at")) or now
        add("product_fact_changed", due, case_ref=m.get("case_ref") or m.get("entity_ref"), ref=f"impact:{_impact_ref(m)}", reason=str(m.get("reason") or m.get("event_ref") or "a fact change awaits the case"))
    entries.sort(key=lambda item: (not item.overdue, item.due_at, item.kind, item.ref))
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return seal(ReviewCalendar, {"as_of": stamp, "horizon_days": horizon_days, "entries": [item.to_dict() for item in entries], "counts": dict(sorted(counts.items()))}, "calendar_digest")


REVIEW_MANIFEST: dict[str, Any] = {
    "schemas": {"assessment": REVIEW_SCHEMA, "state_diff": STATE_DIFF_SCHEMA, "calendar": CALENDAR_SCHEMA},
    "triggers": ["review_due", "fact_changed", "life_event", "product_fact_changed", "product_withdrawn", "quote_expired", "authority_expiring", "fee_consent_renewal", "implemented_terms_differ", "catalog_stale", "approval_ageing", "review_required_flag"],
    "checks": ["facts_unchanged", "product_still_offered", "pricing_unchanged", "suitability_holds", "serviceability_holds", "needs_still_met", "authority_current", "fee_arrangement_current", "holding_matches_implementation", "disclosures_current"],
    "outcome_rule": "readvice_required when any trigger is readvice; client_re_disclosure_required when a life event is declared; adviser_confirms when any trigger asks for confirmation or any check does not hold; advice_holds otherwise",
    "ranked_fields": sorted(RANKED_FIELDS),
    "life_events": {event: list(facts) for event, facts in LIFE_EVENTS.items()},
    "windows_days": {"verification_max_age": VERIFICATION_MAX_AGE_DAYS, "authority_expiring": AUTHORITY_EXPIRING_DAYS, "fee_renewal": FEE_RENEWAL_WINDOW_DAYS, "approval_ageing": APPROVAL_AGEING_DAYS, "quote_validity": QUOTE_VALIDITY_DAYS, "calendar_horizon": DEFAULT_CALENDAR_HORIZON_DAYS},
    "hard_rules": [
        "advice already given is never rewritten: a review says whether re-advice is due and the new advice is a successor case linked by predecessor_case_ref",
        "the diff carries decision facts and commitments only; identity keys in any review input are refused",
        "suitability and needs are re-evaluated with the engine's own functions; serviceability is passed in as a sealed verdict and never computed here",
        "no clock is read: every function takes as_of",
        "a dated input that does not parse is refused (REVIEW_BAD_DATE), never silently dropped; a verification receipt speaks only for an authority the plan holds for the vertical",
        "a review never crosses a jurisdiction or a vertical: the states and the record agree or the review is refused and a successor case is opened",
    ],
    "not_claimed": "a review assessment is evidence for the licensed adviser's decision; it is not advice and it decides nothing",
}

__all__ = [
    "APPROVAL_AGEING_DAYS",
    "AUTHORITY_EXPIRING_DAYS",
    "CALENDAR_SCHEMA",
    "DEFAULT_CALENDAR_HORIZON_DAYS",
    "FEE_RENEWAL_WINDOW_DAYS",
    "FORBIDDEN_REVIEW_KEYS",
    "LIFE_EVENTS",
    "RANKED_FIELDS",
    "REVIEW_MANIFEST",
    "REVIEW_SCHEMA",
    "STATE_DIFF_SCHEMA",
    "VERIFICATION_MAX_AGE_DAYS",
    "AdviceReviewError",
    "CalendarEntry",
    "CheckKey",
    "CheckStatus",
    "FieldChange",
    "Outcome",
    "ReviewAssessment",
    "ReviewCalendar",
    "ReviewCheck",
    "ReviewTrigger",
    "Severity",
    "StateDiff",
    "TriggerKind",
    "life_event_questions",
    "review_assessment",
    "review_calendar",
    "review_receipt",
    "review_triggers",
    "state_diff",
    "successor_intake_receipt",
]
