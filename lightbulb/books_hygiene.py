"""Books hygiene: where the owner's books leave the numbers weaker than they look, in plain words, with the fix.

Every figure the SDK reports is only as good as the ledger under it.  A
small business's books are usually incomplete in a few predictable ways:
months with sales and no costs, no wages recorded because the owner pays
themselves outside payroll, money parked in a suspense or "uncategorised"
account, bank lines never reconciled, tax owed that the cash in the bank
does not cover.  Each makes the margins look better or the cash look
safer than they are, silently.

``assess_books_hygiene`` reads the books snapshots already recorded (one
per month when backfilled) and, when supplied, the ledger's bank
transactions read, and seals one finding per problem it can prove: what it
is, what it does to the owner's numbers, how much money it touches, and the
fix.  It reads nothing and changes nothing.  A problem it has no evidence
for is not raised, and what it could not check is listed, so "no findings"
is never claimed on thin evidence.  ``trust`` is a plain grade from the
findings: ``good`` with none, ``fair`` with only minor ones, ``weak`` once
any finding would move a headline figure.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.company_engine_core import GENESIS_DIGEST, CurrencyCode, OpaqueRef, Sha256Digest, ShortText, StrictModel, decimal_value, detached, parsed, seal, sealed_digest, skip_digests, stable_digest, timestamp

BOOKS_HYGIENE_SCHEMA = "lightbulb.books_hygiene.v1"
BOOKS_HYGIENE_MANIFEST: dict[str, Any] = {"engine": "books_hygiene", "kind": "intelligence_document", "reads": ("books_snapshot",), "writes": ()}
BANK_TRANSACTION_TOOLS: tuple[str, ...] = ("xero.list_bank_transactions",)
Severity = Literal["high", "medium", "low"]
Trust = Literal["good", "fair", "weak"]
# account names that hold money nobody has put anywhere yet
CATCH_ALL = re.compile(r"\b(suspense|uncategori[sz]ed|unclassified|sundr(y|ies)|ask my accountant|to be allocated|clearing|miscellaneous|general expenses?)\b", re.IGNORECASE)
_PL_CLASSES = ("revenue", "other_income", "cost_of_sales", "operating_expense", "other_expense")
_CENT = Decimal("0.01")
UNRECONCILED_STALE_DAYS = 30


class BooksHygieneError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise BooksHygieneError(code, message)


def _tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _money(value: Decimal, currency: str) -> str:
    rounded = value.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return ("-" if rounded < 0 else "") + f"{currency} {abs(rounded):,}"


class HygieneFinding(StrictModel):
    code: ShortText
    severity: Severity
    what: ShortText
    effect: ShortText
    fix: ShortText
    money: Decimal | None = None
    windows: tuple[OpaqueRef, ...] = Field(default_factory=tuple, max_length=36)

    @field_validator("money", mode="before")
    @classmethod
    def _numbers(cls, value: Any) -> Decimal | None:
        return None if value is None else decimal_value(value, field_name="money", allow_negative=True)

    @field_validator("windows", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)


class BooksHygiene(StrictModel):
    schema_id: str = Field(default=BOOKS_HYGIENE_SCHEMA, alias="schema")
    company_ref: OpaqueRef
    currency: CurrencyCode
    as_of: str
    windows: tuple[OpaqueRef, ...] = Field(max_length=36)
    findings: tuple[HygieneFinding, ...] = Field(default_factory=tuple, max_length=16)
    not_checked: tuple[ShortText, ...] = Field(default_factory=tuple, max_length=8)
    trust: Trust
    verdict: ShortText
    source_digests: tuple[Sha256Digest, ...] = Field(default_factory=tuple, max_length=40)
    hygiene_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("windows", "findings", "not_checked", "source_digests", mode="before")
    @classmethod
    def _sequences(cls, value: object) -> object:
        return _tuple(value)

    @model_validator(mode="after")
    def _guard(self, info: ValidationInfo) -> "BooksHygiene":
        if self.trust != _trust(self.findings):
            raise ValueError("trust is graded from the findings")
        if not skip_digests(info) and self.hygiene_digest != sealed_digest(BooksHygiene, self, "hygiene_digest"):
            raise ValueError("hygiene_digest must commit the exact assessment")
        return self

    def render(self) -> str:
        lines = [f"**Books hygiene** ({self.company_ref}, {len(self.windows)} month(s) to {self.as_of[:10]}): {self.verdict}"]
        lines.extend(f"- {row.what} {row.effect} Fix: {row.fix}" for row in self.findings)
        lines.extend(f"- not checked: {item}" for item in self.not_checked)
        return "\n".join(lines)


def _trust(findings: Sequence[HygieneFinding | Mapping[str, Any]]) -> str:
    severities = {str(dict(detached(row))["severity"]) if not isinstance(row, HygieneFinding) else row.severity for row in findings}
    return "weak" if severities & {"high", "medium"} else ("fair" if severities else "good")


def _bank_lines(source: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str]:
    from lightbulb.bank_reconciliation import _normalize, _page_rows
    from lightbulb.company_execution_bridge import ObservationProvenance

    raw = dict(detached(source))
    _require(raw.get("provenance") is not None and raw.get("payload") is not None, "SOURCE_NOT_SEALED", "the bank transactions read carries its provenance and the exact payload")
    read = ObservationProvenance.model_validate(raw["provenance"])
    _require(read.source_tool in BANK_TRANSACTION_TOOLS, "SOURCE_TOOL_MISMATCH", f"bank lines are read with {list(BANK_TRANSACTION_TOOLS)}; the read names {read.source_tool}")
    _require(read.output_digest == stable_digest(detached(raw["payload"])), "SOURCE_DIGEST_MISMATCH", "the bank lines must be the exact output the read returned")
    rows = []
    for item in _page_rows(read.source_tool, raw["payload"]):
        if str(item.get("Status") or "").upper() in ("DELETED", "VOIDED"):
            continue
        rows.append(_normalize(read.source_tool, item))
    return rows, read.provenance_digest


def assess_books_hygiene(*, company_ref: str, currency: str, as_of: str, snapshots: Sequence[Mapping[str, Any]], bank_transactions: Mapping[str, Any] | None = None) -> BooksHygiene:
    """One finding per problem the recorded books (and, when supplied, the bank transactions read) prove, each with its effect on the owner's numbers and the fix."""

    from lightbulb.books_snapshot import verify_books_snapshot

    at = timestamp(as_of, field_name="as_of")
    currency = str(currency).upper()
    books = sorted((verify_books_snapshot({key: value for key, value in dict(detached(item)).items() if key not in {"version", "summary", "provider_effect_executed"}}) for item in snapshots), key=lambda row: row.window_start)
    _require(bool(books), "BOOKS_MISSING", "hygiene reads the recorded books; record at least one month first")
    for row in books:
        _require(row.company_ref == company_ref and row.currency == currency, "SOURCE_SCOPE_MISMATCH", f"the books for {row.period_label} name another company or currency")
    refs = [f"books:{row.window_start[:10]}:{row.window_end[:10]}" for row in books]
    digests = [row.snapshot_digest for row in books]
    findings: list[dict[str, Any]] = []
    not_checked: list[str] = []

    # months that sold something and recorded no cost at all
    # both month checks use the snapshot's own findings, so hygiene and the books never disagree on what "no costs" means
    codes_by_month = [{finding.code for finding in row.findings} for row in books]
    empty = [(ref, row) for ref, row, codes in zip(refs, books, codes_by_month) if "NO_COSTS_RECORDED" in codes]
    if empty:
        sales = sum((row.revenue for _ref, row in empty), Decimal("0"))
        findings.append({"code": "MONTHS_WITHOUT_COSTS", "severity": "high", "what": f"{len(empty)} month(s) record sales of {_money(sales, currency)} and no costs at all.", "effect": "Every margin for those months shows as nearly 100%, and break-even looks closer than it is.", "fix": "Enter the bills and card spend for those months, or check they were coded to the right account.", "money": str(sales.quantize(_CENT)), "windows": [ref for ref, _row in empty]})

    # no labour anywhere: the cost of the owner's (or anyone's) time is missing
    if all("NO_LABOUR_COST_RECORDED" in codes for codes in codes_by_month) and any(row.revenue > 0 for row in books):
        findings.append({"code": "NO_LABOUR_RECORDED", "severity": "medium", "what": f"None of the {len(books)} month(s) records wages, super or contractor costs.", "effect": "If people (including you) did the work, its cost is missing, so margins and the rate you need to charge are both understated.", "fix": "Record wages or contractor bills as they are paid; if you pay yourself, record it as wages or drawings consistently.", "windows": refs})

    # money parked in catch-all accounts, on the income statement or the balance sheet
    parked: dict[str, Decimal] = {}
    for row in books:
        for line in row.lines:
            if line.amount == 0 or not CATCH_ALL.search(line.name):
                continue
            # income and costs add up across the months; a balance is taken as at the latest month (the books run oldest first)
            parked[line.name] = parked.get(line.name, Decimal("0")) + line.amount if line.account_class in _PL_CLASSES else line.amount
    if parked:
        total = sum((abs(value) for value in parked.values()), Decimal("0"))
        names = ", ".join(sorted(parked)[:3])
        findings.append({"code": "MONEY_IN_CATCH_ALL_ACCOUNTS", "severity": "medium", "what": f"{_money(total, currency)} sits in catch-all accounts ({names}).", "effect": "Money nobody has put in the right place hides a cost or an income from the figures that use it.", "fix": "Recode each item in those accounts to where it belongs, then clear them to zero.", "money": str(total.quantize(_CENT))})

    # tax owed that the cash does not cover, from the latest balance sheet
    latest = next((row for row in reversed(books) if row.balances_as_at), None)
    if latest is None:
        not_checked.append("whether your cash covers the tax you owe: no balance sheet is on record")
    elif latest.tax_owed is not None and latest.cash is not None and latest.tax_owed > latest.cash:
        gap = latest.tax_owed - latest.cash
        findings.append({"code": "TAX_NOT_COVERED", "severity": "high", "what": f"You owe {_money(latest.tax_owed, currency)} in tax and hold {_money(latest.cash, currency)} in the bank.", "effect": "The cash you see is already spoken for, and more.", "fix": f"Set aside {_money(gap, currency)} before the next tax due date, or arrange a payment plan now.", "money": str(gap.quantize(_CENT)), "windows": [f"books:{latest.window_start[:10]}:{latest.window_end[:10]}"]})

    # unreconciled bank lines, when the read is supplied
    if bank_transactions is None:
        not_checked.append("unreconciled bank lines: no bank transactions read was supplied")
    else:
        lines, digest = _bank_lines(bank_transactions)
        digests.append(digest)
        open_lines = [line for line in lines if not line["provider_reconciled"] and (parsed(at) - parsed(line["occurred_at"])).days >= UNRECONCILED_STALE_DAYS]
        if open_lines:
            amount = sum((abs(Decimal(line["amount"])) for line in open_lines), Decimal("0"))
            oldest = min(line["occurred_at"] for line in open_lines)[:10]
            findings.append({"code": "UNRECONCILED_BANK_LINES", "severity": "medium" if len(open_lines) > 5 else "low", "what": f"{len(open_lines)} bank line(s) worth {_money(amount, currency)} are over {UNRECONCILED_STALE_DAYS} days old and not reconciled, the oldest from {oldest}.", "effect": "Until they are matched, the books may be missing sales, costs or both.", "fix": "Reconcile them in your ledger's bank screen, oldest first.", "money": str(amount.quantize(_CENT))})

    # the snapshot's own findings that belong here, when not already covered
    codes = {row["code"] for row in findings}
    for row in books[-1:]:
        for finding in row.findings:
            if finding.code == "SUSPENSE_BALANCE" and "MONEY_IN_CATCH_ALL_ACCOUNTS" not in codes:
                findings.append({"code": "MONEY_IN_CATCH_ALL_ACCOUNTS", "severity": "medium", "what": finding.detail[:300], "effect": "Money nobody has put in the right place hides a cost or an income from the figures that use it.", "fix": "Recode each item in the suspense account to where it belongs, then clear it to zero."})

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda row: (order[row["severity"]], row["code"]))
    trust = _trust(findings)
    verdict = ("your books hold up: nothing found that would move a headline figure" if trust == "good" else f"{len(findings)} thing(s) in your books make the numbers weaker than they look; first: {findings[0]['what']}")[:300]
    return seal(BooksHygiene, {"company_ref": company_ref, "currency": currency, "as_of": at, "windows": refs, "findings": [{key: value for key, value in row.items() if value is not None} for row in findings], "not_checked": not_checked, "trust": trust, "verdict": verdict, "source_digests": digests[:40]}, "hygiene_digest")


def verify_books_hygiene(value: Any) -> BooksHygiene:
    return value if isinstance(value, BooksHygiene) else BooksHygiene.model_validate({key: item for key, item in dict(detached(value)).items() if key not in {"summary", "provider_effect_executed", "documents_built"}})


__all__ = ["BANK_TRANSACTION_TOOLS", "BOOKS_HYGIENE_MANIFEST", "BOOKS_HYGIENE_SCHEMA", "BooksHygiene", "BooksHygieneError", "HygieneFinding", "assess_books_hygiene", "verify_books_hygiene"]
