"""Tie-out: every document's headline total against the books, with the difference, the tolerance, and the likely reasons.

A margin report built from orders and a books snapshot built from the
ledger describe the same company over the same window.  When their
revenues differ, one of them is wrong or incomplete, and an owner who acts
on the wrong one loses money.  ``tie_out_documents`` puts each document's
comparable total beside the books' figure for the same window and states
the difference, whether it sits inside the plan's tolerance, and the
reasons such a difference usually has: orders not yet invoiced, invoices
with no order, tax on one side and not the other, timing across a period
end, a currency converted differently.  It names reasons; it never picks
one, because the ledger and the operational system carry no link that
would prove which.

The tie-out is itself a sealed document, its lines are digest-bound to the
documents they compared, and it raises one review action per line outside
tolerance so the reconciliation becomes work someone owns.  Nothing here
reads a provider or persists anything.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, MONEY_QUANTUM, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, timestamp

TIE_OUT_PLAN_SCHEMA = "lightbulb.tie_out_plan.v1"
TIE_OUT_SCHEMA = "lightbulb.ledger_tie_out.v1"
TIE_OUT_MANIFEST: dict[str, Any] = {"engine": "ledger_tie_out", "kind": "intelligence_document", "reads": ("books_snapshot", "product_margin", "services_margin", "break_even", "working_capital"), "writes": ()}
TIE_STATUSES: tuple[str, ...] = ("tied", "outside_tolerance", "not_comparable")
TieStatus = Literal["tied", "outside_tolerance", "not_comparable"]
_PERCENT = Decimal("0.01")

# What each document's total is compared with in the books, and why the two usually differ.
COMPARISONS: dict[str, dict[str, Any]] = {
    "product_margin": {"document_field": ("net_revenue", "unallocated_revenue"), "books_field": "revenue", "label": "product net revenue (with revenue no SKU claimed) against the books' revenue", "reasons": ("orders shipped but not yet invoiced, or invoiced but not yet shipped", "sales invoiced outside the storefront (manual invoices, services) appear only in the books", "refunds netted in the report but posted to a separate account in the books", "the report is tax-exclusive by construction; check that the ledger's revenue accounts are too", "orders dated by shipment in the report and by invoice date in the books")},
    "product_cost": {"document": "product_margin", "document_field": "cost_of_goods", "books_field": "cost_of_sales", "label": "product cost of goods against the books' cost of sales", "reasons": ("the report costs goods at the blended landed unit cost while the books post purchases when billed", "freight, duty or packaging in one and not the other", "stock write-downs posted in the books with no order behind them")},
    "services_margin": {"document_field": "recognisable_value", "books_field": "revenue", "label": "services recognisable value against the books' revenue", "reasons": ("work delivered but not yet invoiced, or invoiced ahead of delivery", "retainers and deposits recognised on different dates", "expenses recharged to clients invoiced in the books but not effort in the engagements")},
    "break_even": {"document_field": "fixed_cost", "books_field": "fixed_costs", "label": "break-even fixed cost against the books' fixed cost", "reasons": ("a cost register covers a period that only partly overlaps the window and was prorated", "a register source kind is excluded as variable while the books class it as fixed, or the reverse", "costs in the books with no register behind them (bank fees, depreciation, interest)")},
    "working_capital_receivables": {"document": "working_capital", "lever": "receivables", "books_field": "receivables", "label": "open receivables against the books' receivable balance", "reasons": ("invoices in the ledger that were never opened as collection cases", "credit notes applied in the ledger but not recorded against the case", "the books balance is as at the month end and the cases are as of the window's last day")},
    "working_capital_payables": {"document": "working_capital", "lever": "payables", "books_field": "payables", "label": "open payables against the books' payable balance", "reasons": ("bills in the ledger that were never adopted as payable cases", "bills paid at the provider while the case still awaits its payment receipt", "the books balance is as at the month end and the cases are as of the window's last day")},
}


class TieOutError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise TieOutError(code, message)


def _money(value: Any) -> Decimal:
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class TieOutPlan(StrictModel):
    schema_id: str = Field(default=TIE_OUT_PLAN_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    tolerance_percent: Decimal = Field(default=Decimal("2.00"), validate_default=True)
    tolerance_amount: Decimal = Field(default=Decimal("50.00"), validate_default=True)
    plan_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("tolerance_percent", "tolerance_amount", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal:
        return decimal_value(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "TieOutPlan":
        if not skip_digests(info) and self.plan_digest != sealed_digest(TieOutPlan, self, "plan_digest"):
            raise ValueError("plan_digest must commit the exact plan")
        return self


def compile_tie_out_plan(company_ref: str, *, currency: str, overrides: Mapping[str, Any] | None = None) -> TieOutPlan:
    return seal(TieOutPlan, {"company_ref": company_ref, "currency": str(currency).upper(), **dict(overrides or {})}, "plan_digest")


class TieLine(StrictModel):
    comparison: ShortText
    document: ShortText
    document_digest: Sha256Digest | None = None
    label: ShortText
    document_amount: Decimal | None = None
    books_amount: Decimal | None = None
    difference: Decimal | None = None
    difference_percent: Decimal | None = None
    status: TieStatus
    note: ShortText
    likely_reasons: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)

    @field_validator("likely_reasons", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("document_amount", "books_amount", "difference", "difference_percent", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)


class LedgerTieOut(StrictModel):
    schema_id: str = Field(default=TIE_OUT_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    window_start: str
    window_end: str
    as_of: str
    plan_digest: Sha256Digest
    books_digest: Sha256Digest
    lines: tuple[TieLine, ...] = Field(max_length=24)
    tied: int = Field(ge=0)
    outside_tolerance: int = Field(ge=0)
    not_comparable: int = Field(ge=0)
    largest_difference: Decimal | None = None
    verdict: ShortText
    recommendations: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=24)
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=12)
    tie_out_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("lines", "recommendations", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @field_validator("largest_difference", mode="before")
    @classmethod
    def _numbers(cls, value: Any, info: ValidationInfo) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name=str(info.field_name), allow_negative=True)

    @field_validator("window_start", "window_end", "as_of")
    @classmethod
    def _stamps(cls, value: str, info: ValidationInfo) -> str:
        return timestamp(value, field_name=str(info.field_name))

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "LedgerTieOut":
        counts = {status: sum(1 for line in self.lines if line.status == status) for status in TIE_STATUSES}
        if (self.tied, self.outside_tolerance, self.not_comparable) != (counts["tied"], counts["outside_tolerance"], counts["not_comparable"]):
            raise ValueError("the counts count the lines")
        for line in self.lines:
            if line.document_amount is not None and line.books_amount is not None and line.difference != _money(line.document_amount - line.books_amount):
                raise ValueError("difference is the document amount less the books amount")
        if not skip_digests(info) and self.tie_out_digest != sealed_digest(LedgerTieOut, self, "tie_out_digest"):
            raise ValueError("tie_out_digest must commit the exact document")
        return self

    def line(self, comparison: str) -> TieLine:
        found = next((item for item in self.lines if item.comparison == comparison), None)
        if found is None:
            raise LookupError(f"no tie-out line for {comparison}")
        return found

    def render(self) -> str:
        lines = [f"**Tie-out to the books** ({self.company_ref}, {self.window_start[:10]} to {self.window_end[:10]}): {self.verdict}"]
        lines.extend(f"- [{item.status}] {item.note}" for item in self.lines)
        return "\n".join(lines)


def tie_out_documents(plan: TieOutPlan | Mapping[str, Any], *, books: Mapping[str, Any] | Any, documents: Mapping[str, Mapping[str, Any] | Any], as_of: str) -> LedgerTieOut:
    """Each supplied document's comparable totals beside the books' figures for the same window, sealed."""

    from lightbulb.books_snapshot import verify_books_snapshot

    parsed_plan = plan if isinstance(plan, TieOutPlan) else TieOutPlan.model_validate(detached(plan))
    at = timestamp(as_of, field_name="as_of")
    snapshot = verify_books_snapshot(books)
    _require(snapshot.company_ref == parsed_plan.company_ref and snapshot.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", "the books name another company or currency")
    start, end = snapshot.window_start, snapshot.window_end
    supplied = {str(kind): value for kind, value in dict(documents).items()}
    unknown = sorted(set(supplied) - {"product_margin", "services_margin", "break_even", "working_capital"})
    _require(not unknown, "DOCUMENT_KIND_UNKNOWN", f"the tie-out compares product_margin, services_margin, break_even and working_capital, not {unknown}")
    _require(bool(supplied), "DOCUMENTS_MISSING", "supply at least one document to tie out")

    verified: dict[str, Any] = {}
    digests: list[str] = [snapshot.snapshot_digest]
    for kind, value in supplied.items():
        if kind == "product_margin":
            from lightbulb.product_margin import verify_product_margin

            doc, digest = verify_product_margin(value), None
            digest = doc.report_digest
        elif kind == "services_margin":
            from lightbulb.services_margin import verify_services_margin

            doc = verify_services_margin(value)
            digest = doc.margin_digest
        elif kind == "break_even":
            from lightbulb.break_even import verify_break_even

            doc = verify_break_even(value)
            digest = doc.break_even_digest
        else:
            from lightbulb.working_capital import verify_working_capital

            doc = verify_working_capital(value)
            digest = doc.capital_digest
        _require(doc.company_ref == parsed_plan.company_ref and doc.currency == parsed_plan.currency, "SOURCE_SCOPE_MISMATCH", f"the {kind} document names another company or currency")
        _require(doc.window_start == start and doc.window_end == end, "REPORT_WINDOW_MISMATCH", f"the {kind} document covers {doc.window_start[:10]} to {doc.window_end[:10]}, the books {start[:10]} to {end[:10]}")
        verified[kind] = (doc, digest)
        digests.append(digest)

    lines: list[dict[str, Any]] = []
    recommendations: list[str] = []
    for name, spec in COMPARISONS.items():
        kind = spec.get("document", name)
        if kind not in verified:
            continue
        doc, digest = verified[kind]
        if kind == "break_even" and (doc.fixed_cost_basis == "books" or not doc.fixed_cost_known):
            lines.append({"comparison": name, "document": kind, "document_digest": digest, "label": spec["label"], "status": "not_comparable", "note": f"{spec['label']}: " + ("the fixed cost came from the books, so the two are the same figure" if doc.fixed_cost_basis == "books" else "the document's fixed cost is unknown"), "likely_reasons": []})
            continue
        if "lever" in spec:
            lever = next((row for row in doc.levers if row.lever == spec["lever"]), None)
            if lever is None or lever.basis == "books" or lever.cases == 0:
                lines.append({"comparison": name, "document": kind, "document_digest": digest, "label": spec["label"], "status": "not_comparable", "note": f"{spec['label']}: " + ("the lever came from the books, so the two are the same figure" if lever is not None and lever.basis == "books" else "no cases in the chain to compare"), "likely_reasons": []})
                continue
            document_amount = _money(lever.balance)
        else:
            fields = spec["document_field"] if isinstance(spec["document_field"], tuple) else (spec["document_field"],)
            document_amount = _money(sum((Decimal(str(getattr(doc, field))) for field in fields), Decimal("0")))
        books_amount = getattr(snapshot, spec["books_field"])
        if books_amount is None:
            lines.append({"comparison": name, "document": kind, "document_digest": digest, "label": spec["label"], "document_amount": str(document_amount), "status": "not_comparable", "note": f"{spec['label']}: the books do not state {spec['books_field']} (no account is mapped to it)", "likely_reasons": []})
            continue
        books_amount = _money(books_amount)
        difference = _money(document_amount - books_amount)
        base = max(abs(books_amount), abs(document_amount))
        percent = None if base == 0 else (abs(difference) / base * 100).quantize(_PERCENT, rounding=ROUND_HALF_UP)
        inside = abs(difference) <= parsed_plan.tolerance_amount or (percent is not None and percent <= parsed_plan.tolerance_percent)
        status = "tied" if inside else "outside_tolerance"
        note = f"{spec['label']}: {document_amount} against {books_amount} {parsed_plan.currency}, difference {difference}" + ("" if percent is None else f" ({percent}%)") + (", inside tolerance" if inside else f", outside the {parsed_plan.tolerance_percent}% / {parsed_plan.tolerance_amount} tolerance")
        lines.append({"comparison": name, "document": kind, "document_digest": digest, "label": spec["label"], "document_amount": str(document_amount), "books_amount": str(books_amount), "difference": str(difference), "difference_percent": None if percent is None else str(percent), "status": status, "note": note[:300], "likely_reasons": [] if inside else list(spec["reasons"])})
        if not inside:
            recommendations.append(f"{spec['label']}: reconcile {abs(difference)} {parsed_plan.currency}; usually {spec['reasons'][0]}"[:300])
    counts = {status: sum(1 for line in lines if line["status"] == status) for status in TIE_STATUSES}
    differences = [abs(Decimal(line["difference"])) for line in lines if line.get("difference") is not None]
    largest = max(differences) if differences else None
    verdict = f"{counts['tied']} tied, {counts['outside_tolerance']} outside tolerance, {counts['not_comparable']} not comparable" + ("" if largest is None else f"; largest difference {largest} {parsed_plan.currency}")
    if not recommendations:
        recommendations.append("every comparable total ties to the books inside tolerance" if counts["tied"] else "nothing could be compared: the documents and the books draw on the same figures or the books do not state the balance")
    payload = {"company_ref": parsed_plan.company_ref, "currency": parsed_plan.currency, "window_start": start, "window_end": end, "as_of": at, "plan_digest": parsed_plan.plan_digest, "books_digest": snapshot.snapshot_digest, "lines": lines, "tied": counts["tied"], "outside_tolerance": counts["outside_tolerance"], "not_comparable": counts["not_comparable"], "largest_difference": None if largest is None else str(largest), "verdict": verdict[:300], "recommendations": recommendations[:24], "source_digests": digests}
    return seal(LedgerTieOut, {key: value for key, value in payload.items() if value is not None}, "tie_out_digest")


def verify_ledger_tie_out(value: Any) -> LedgerTieOut:
    return value if isinstance(value, LedgerTieOut) else LedgerTieOut.model_validate(dict(detached(value)))


__all__ = ["COMPARISONS", "TIE_OUT_MANIFEST", "TIE_OUT_PLAN_SCHEMA", "TIE_OUT_SCHEMA", "TIE_STATUSES", "LedgerTieOut", "TieLine", "TieOutError", "TieOutPlan", "compile_tie_out_plan", "tie_out_documents", "verify_ledger_tie_out"]
