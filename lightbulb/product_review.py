"""The owner's product review: what shipped, what users said, what broke, what is queued.

The software factory leaves its traces in several documents: the change
candidates and compiled requests (with the mandate's answer and whether the
platform ran them), the platform's grant ledger (what each run ended as), the
signals the company's apps report, the error rollup, and each app's latest
release against the one before.  The review reads them together and ranks
what needs the owner by evidence: a release that regressed first (with the
release to roll back to, a decision the factory never takes alone), then
error spikes and incidents no one has picked up, then changes waiting on the
owner's budget, then what users asked for.  Nothing is built, sent or
deployed here; deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, seal, sealed_digest, skip_digests, timestamp

PRODUCT_REVIEW_SCHEMA = "lightbulb.product_review.v1"
PRODUCT_REVIEW_MANIFEST: dict[str, Any] = {"engine": "product_review", "kind": "intelligence_document", "reads": ("change_candidate", "software_production_request", "app_signal_batch"), "writes": ()}
ItemKind = Literal["roll_back", "fix_errors", "approve_budget", "decide_request"]
_RANK = {"roll_back": 0, "fix_errors": 1, "approve_budget": 2, "decide_request": 3}
MAX_ITEMS = 12


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class ReviewItem(StrictModel):
    rank: int = Field(ge=1, le=MAX_ITEMS)
    kind: ItemKind
    subject: ShortText
    evidence: ShortText
    money_at_stake: Decimal = Field(default=Decimal("0"), validate_default=True)
    ref: ShortText

    @field_validator("money_at_stake", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal:
        return decimal_value(value, field_name="money_at_stake")


class ProductReview(StrictModel):
    schema_id: str = Field(default=PRODUCT_REVIEW_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    as_of: str
    window_days: int = Field(ge=1, le=365)
    shipped: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    said: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    broke: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    queued: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=50)
    items: tuple[ReviewItem, ...] = Field(default_factory=tuple, max_length=MAX_ITEMS)
    counts: dict[str, int]
    verdict: ShortText
    review_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("shipped", "said", "broke", "queued", "items", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "ProductReview":
        if [item.rank for item in self.items] != list(range(1, len(self.items) + 1)):
            raise ValueError("items are ranked from one")
        if not skip_digests(info) and self.review_digest != sealed_digest(ProductReview, self, "review_digest"):
            raise ValueError("review_digest must commit the exact review")
        return self

    def render(self) -> str:
        lines = [f"**Product review** ({self.company_ref}, {self.window_days} days to {self.as_of[:10]}): {self.verdict}"]
        for title, rows in (("Shipped", self.shipped), ("Users said", self.said), ("Broke", self.broke), ("Queued", self.queued)):
            if rows:
                lines.append(f"- {title}: " + "; ".join(rows[:5]) + (f" (+{len(rows) - 5} more)" if len(rows) > 5 else ""))
        for item in self.items[:5]:
            lines.append(f"{item.rank}. {item.subject} ({item.evidence})")
        return "\n".join(lines)


def build_product_review(*, company_ref: str, as_of: str, window_days: int = 7, changes: Mapping[str, Any] | None = None, signals_summary: Mapping[str, Any] | None = None, errors: Mapping[str, Any] | None = None, releases: Sequence[Mapping[str, Any]] = (), platform_grants: Sequence[Mapping[str, Any]] = ()) -> ProductReview:
    """The week's software in the owner's terms, ranked by evidence; every input is optional and what is missing is simply not said."""

    at = timestamp(as_of, field_name="as_of")
    changes = {} if changes is None else dict(detached(changes))
    candidates = [dict(row) for row in changes.get("candidates", ())]
    requests = [dict(row) for row in changes.get("requests", ())]
    shipped: list[str] = []
    said: list[str] = []
    broke: list[str] = []
    queued: list[str] = []
    items: list[dict[str, Any]] = []

    # shipped: what the platform's ledger says each run ended as, else what the mandate log says was dispatched
    outcomes = {str(row.get("request_digest")): dict(row) for row in platform_grants}
    for row in requests:
        digest = str(row.get("request_digest", ""))
        grant = outcomes.get(digest)
        if grant is not None and grant.get("outcome") == "draft_pr_opened":
            shipped.append(f"{row.get('title')} (draft pull request open for review)")
        elif grant is not None and grant.get("state") in {"consumed", "revoked", "expired"}:
            shipped.append(f"{row.get('title')} (run ended: {grant.get('outcome') or grant.get('state')})")
        elif row.get("dispatched"):
            shipped.append(f"{row.get('title')} (being built)")

    # said: new reports from users, the words' kind; broke: incidents and error spikes as candidates
    for row in candidates:
        if row.get("lifecycle") != "new":
            continue
        if row.get("source") in {"incident", "error_signal"}:
            broke.append(str(row.get("title"))[:200])
            items.append({"kind": "fix_errors", "subject": f"Look at {row.get('title')}"[:300], "evidence": f"reported through {row.get('source')} on {str(row.get('received_at', ''))[:10]}"[:300], "money_at_stake": "0", "ref": f"candidate:{str(row.get('candidate_ref', ''))[:12]}"})
        else:
            said.append(f"{row.get('kind')}: {row.get('title')}"[:300])
            items.append({"kind": "decide_request", "subject": f"Build or decline: {row.get('title')}"[:300], "evidence": f"{row.get('kind')} from {row.get('source')} on {str(row.get('received_at', ''))[:10]}"[:300], "money_at_stake": "0", "ref": f"candidate:{str(row.get('candidate_ref', ''))[:12]}"})

    # broke: signatures past the threshold that are not yet candidates, and releases that regressed
    for row in (errors or {}).get("rows", ()):
        row = dict(row)
        if row.get("over_threshold"):
            line = f"{row.get('error_signature')} x{row.get('count')} in {row.get('app_ref')}"
            if not any(str(row.get("error_signature")) in item for item in broke):
                broke.append(line[:300])
    for health in releases:
        health = dict(health)
        release = dict(health.get("release") or {})
        if health.get("verdict") == "regressed":
            broke.append(f"release {release.get('release_ref')} of {health.get('app_ref')} regressed: {health.get('reason')}"[:300])
            items.append({"kind": "roll_back", "subject": f"Roll {health.get('app_ref')} back to {health.get('rollback_to')}?"[:300], "evidence": str(health.get("reason"))[:300], "money_at_stake": "0", "ref": f"release:{release.get('release_ref')}"})

    # queued: changes waiting on the owner's budget or on the platform
    for row in requests:
        decision = dict(row.get("decision") or {})
        if decision.get("autonomy") == "ask":
            queued.append(f"{row.get('title')} (waiting on your budget of {decision.get('money')})"[:300])
            items.append({"kind": "approve_budget", "subject": f"Approve {decision.get('money')} to build: {row.get('title')}"[:300], "evidence": str(decision.get("reason", ""))[:300], "money_at_stake": str(decision.get("money", "0")), "ref": f"change:{str(row.get('request_digest', ''))[:12]}"})
        elif decision.get("autonomy") == "act" and not row.get("dispatched") and str(row.get("request_digest")) not in outcomes:
            queued.append(f"{row.get('title')} (ready to build)"[:300])

    items.sort(key=lambda item: (_RANK[item["kind"]], -Decimal(item["money_at_stake"]), item["ref"]))
    ranked = [{**item, "rank": index + 1} for index, item in enumerate(items[:MAX_ITEMS])]
    apps = [dict(row) for row in (signals_summary or {}).get("apps", ())]
    counts = {"shipped": len(shipped), "said": len(said), "broke": len(broke), "queued": len(queued), "apps": len(apps), "feedback": sum(int(row.get("feedback", 0)) for row in apps), "errors": sum(int(row.get("errors", 0)) for row in apps)}
    if ranked:
        verdict = f"{len(ranked)} thing(s) for you; first: {ranked[0]['subject']}"
    elif any(counts[key] for key in ("shipped", "said", "broke", "queued")):
        verdict = "nothing needs you; the factory has it in hand"
    else:
        verdict = "a quiet week: nothing shipped, reported or broken"
    return seal(ProductReview, {"company_ref": company_ref, "as_of": at, "window_days": int(window_days), "shipped": shipped[:50], "said": said[:50], "broke": broke[:50], "queued": queued[:50], "items": ranked, "counts": counts, "verdict": verdict[:300]}, "review_digest")


def verify_product_review(value: Any) -> ProductReview:
    return value if isinstance(value, ProductReview) else ProductReview.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "releases", "missing"}})


__all__ = ["MAX_ITEMS", "PRODUCT_REVIEW_MANIFEST", "PRODUCT_REVIEW_SCHEMA", "ProductReview", "ReviewItem", "build_product_review", "verify_product_review"]
