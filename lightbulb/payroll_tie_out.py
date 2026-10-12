"""Check observed payroll, statutory dates and books; never calculate deductions.

Scope envelopes come from the host's authenticated read context. They are not
authorization. An unpaid-run inventory is a stated reconciliation basis, never
a receipt proving remittance. Canada previews are explicitly synthetic until
the platform supplies a governed component-level payroll observation.
"""
from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any, Literal, Mapping, Sequence

from pydantic import Field, ValidationInfo, field_validator, model_validator

from lightbulb.books_snapshot import BooksSnapshot
from lightbulb.company_engine_core import EngineScope, GENESIS_DIGEST, OpaqueRef, Sha256Digest, StrictModel, detached, same_scope, seal, sealed_digest, skip_digests, stable_digest, timestamp
from lightbulb.company_execution_bridge import ObservationProvenance
from lightbulb.compliance_calendar import ComplianceCalendarPlan
from lightbulb.payroll_run_chain import cost_receipt, draft_receipt

COMPONENT_KINDS = {
    "AU": {"income_tax": "payg_withholding", "super_employer": "superannuation"},
    "CA": {"income_tax": "payroll", "cpp_employee": "payroll", "cpp_employer": "payroll", "cpp2_employee": "payroll", "cpp2_employer": "payroll", "ei_employee": "payroll", "ei_employer": "payroll", "qc_income_tax": "qc_payroll", "qpp_employee": "qc_payroll", "qpp_employer": "qc_payroll", "qpp2_employee": "qc_payroll", "qpp2_employer": "qc_payroll", "qpip_employee": "qc_payroll", "qpip_employer": "qc_payroll", "qc_hsf": "qc_payroll", "on_eht": "on_eht", "bc_eht": "bc_eht", "mb_health": "mb_he", "nl_hapset": "nl_hapset"},
}
PLATFORM_DEPENDENCY = "Canada needs a governed QuickBooks payroll read with hashed worker/run identities, complete component totals, applicability/exemptions, pay dates, currency, scope and provenance. Raw payslips are not admitted."


class PayrollTieOutError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PayrollTieOutError(code)


class LiabilityAccount(StrictModel):
    account_ref: OpaqueRef
    components: tuple[str, ...] = Field(min_length=1, max_length=30)

    @field_validator("components", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return tuple(value)


class UnpaidPayrollBasis(StrictModel):
    """Owner/host-confirmed complete unpaid inventory, not provider proof.

    A listed run/component is wholly unpaid as of the books balance date.
    Partial remittances, unrelated opening balances or adjustments cannot be
    represented here: leave the basis absent and obtain a liability subledger.
    """
    as_of_date: date
    confirmed_by_ref: OpaqueRef
    unpaid_components: dict[str, tuple[str, ...]] = Field(max_length=50)
    complete_inventory_confirmed: bool

    @field_validator("as_of_date", mode="before")
    @classmethod
    def day(cls, value: Any) -> Any:
        return date.fromisoformat(value) if isinstance(value, str) else value

    @field_validator("unpaid_components", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return {key: tuple(items) for key, items in value.items()}


class PayrollCheck(StrictModel):
    check: Literal["deductions", "calendar", "books", "coverage"]
    subject: str
    status: Literal["present", "scheduled", "tied_on_stated_basis", "missing", "outside_tolerance", "not_comparable", "differs", "overdue", "not_applicable"]
    note: str
    run_ref: OpaqueRef | None = None
    component: str | None = None
    account_ref: OpaqueRef | None = None
    payroll_amount: str | None = None
    books_amount: str | None = None
    difference: str | None = None
    obligation_ref: OpaqueRef | None = None
    due_on: str | None = None


class PayrollTieOut(StrictModel):
    schema_id: Literal["lightbulb.payroll_tie_out.v1"] = Field(default="lightbulb.payroll_tie_out.v1", alias="schema")
    scope: EngineScope
    company_ref: OpaqueRef
    jurisdiction: str
    as_of: str
    checks: tuple[PayrollCheck, ...] = Field(max_length=5000)
    source_digests: tuple[Sha256Digest, ...]
    facts_digest: Sha256Digest
    books_balance_date: str | None = None
    unpaid_basis: UnpaidPayrollBasis | None = None
    expected_components: tuple[str, ...] = ()
    exemptions: dict[str, dict[str, str]] = Field(default_factory=dict)
    liability_accounts: tuple[LiabilityAccount, ...] = ()
    fixture_only: bool = False
    deduction_amounts_computed: Literal[False] = False
    deduction_rates_validated: Literal[False] = False
    provider_effect_executed: Literal[False] = False
    report_digest: Sha256Digest = GENESIS_DIGEST

    @field_validator("checks", "source_digests", "expected_components", "liability_accounts", mode="before")
    @classmethod
    def tuples(cls, value: Any) -> Any:
        return tuple(value)

    @field_validator("as_of")
    @classmethod
    def at(cls, value: str) -> str:
        return timestamp(value, field_name="as_of")

    @model_validator(mode="after")
    def guard(self, info: ValidationInfo) -> PayrollTieOut:
        if not skip_digests(info) and self.report_digest != sealed_digest(PayrollTieOut, self, "report_digest"):
            raise ValueError("PAYROLL_TIE_OUT_DIGEST_MISMATCH")
        return self

    def render(self) -> str:
        lines = ["Payroll checks" + (" — synthetic Canada preview" if self.fixture_only else "")]
        if self.books_balance_date:
            lines.append("Books balances as of " + self.books_balance_date + ".")
        if self.unpaid_basis:
            lines.append(f"Unpaid inventory stated by {self.unpaid_basis.confirmed_by_ref} as of {self.unpaid_basis.as_of_date}; complete: {self.unpaid_basis.complete_inventory_confirmed}.")
        lines.append("Expected components: " + ", ".join(self.expected_components))
        for worker, components in sorted(self.exemptions.items()):
            for component, reason in sorted(components.items()):
                lines.append(f"Exemption: {worker}, {component}: {reason}")
        for account in self.liability_accounts:
            lines.append(f"Account mapping: {account.account_ref} = {', '.join(account.components)}")
        for row in self.checks:
            details = [f"run {row.run_ref}" if row.run_ref else "", f"due {row.due_on}" if row.due_on else "",
                       f"payroll {row.payroll_amount} {self.scope.currency}" if row.payroll_amount is not None else "",
                       f"books {row.books_amount}" if row.books_amount is not None else "",
                       f"difference {row.difference}" if row.difference is not None else ""]
            lines.append(f"- {row.subject}: {row.status.replace('_', ' ')}. {'; '.join(d for d in details if d)}. {row.note}")
        lines.append("Presence and reconciliation checks only; deduction rates and tax amounts were not calculated or validated.")
        return "\n".join(lines)


def _scope(envelope: Mapping[str, Any], expected: EngineScope) -> None:
    require(same_scope(EngineScope.model_validate(envelope.get("scope") or {}), expected), "SCOPE_MISMATCH")


def _observed_run(source: Mapping[str, Any], expected: EngineScope, at: str) -> dict[str, Any]:
    _scope(source, expected)
    read = ObservationProvenance.model_validate(source["provenance"])
    require(read.source_tool == "xero.observe_payrun" and read.lane == "governed_read", "GOVERNED_PAYROLL_READ_REQUIRED")
    require(read.completed_at <= at, "PAYROLL_FROM_FUTURE")
    raw = source["payload"]
    # Real production receipt adapters validate the complete posted page,
    # integer minor units, unique worker commitments and conserved totals.
    cost = cost_receipt(read, raw)
    draft = draft_receipt(read, raw)
    require(raw["currency"] == expected.currency == "AUD", "PAYROLL_CURRENCY_MISMATCH")
    require(draft["pay_date"] <= at and draft["period_start"] <= draft["period_end"], "PAYROLL_PERIOD_INVALID")
    require(Decimal(cost["gross"]) == Decimal(cost["net"]) + Decimal(cost["withholding"]) + Decimal(cost["deductions"]), "PAYROLL_GROSS_NET_MISMATCH")
    return {"run_ref": "payrun:" + raw["pay_run_id_sha256"], "payment_date": raw["payment_date"], "period_end": raw["period_end"], "workers": [{"worker_ref": "worker:" + r["employee_id_sha256"], "components": {"income_tax": r["tax_minor"], "super_employer": r["super_minor"]}} for r in raw["workers"]], "source_digest": read.output_digest}


def _calendar(envelope: Mapping[str, Any] | None, expected: EngineScope, company_ref: str, jurisdiction: str) -> tuple[list[dict[str, Any]], str | None, dict[str, Any] | None]:
    if envelope is None:
        return [], None, None
    _scope(envelope, expected)
    plan = ComplianceCalendarPlan.model_validate(envelope["document"])
    require((plan.company_ref, plan.currency, plan.jurisdiction) == (company_ref, expected.currency, jurisdiction), "CALENDAR_SCOPE_MISMATCH")
    if jurisdiction == "AU":
        from lightbulb.australia_obligations import AustraliaObligationsCalendar
        cls, raw = AustraliaObligationsCalendar, plan.australia_calendar
    else:
        from lightbulb.canada_obligations import CanadaObligationsCalendar
        cls, raw = CanadaObligationsCalendar, plan.canada_calendar
    if raw is None:
        return [], plan.plan_digest, None
    calendar = cls.model_validate(raw)
    require(calendar.company_ref == company_ref, "CALENDAR_SCOPE_MISMATCH")
    return [r.to_dict() for r in calendar.obligations], plan.plan_digest, calendar.facts


def _covers(row: Mapping[str, Any], payday: str, jurisdiction: str) -> bool:
    """Match a period, never infer a deadline. Old AU rows without bounds fail closed."""
    end = row.get("period_end")
    start = row.get("period_start")
    if end and not start and jurisdiction == "CA":
        last = date.fromisoformat(end)
        remitter = row.get("remitter_basis")
        if remitter == "regular":
            start = last.replace(day=1).isoformat()
        elif remitter == "quarterly":
            start = last.replace(month=((last.month - 1) // 3) * 3 + 1, day=1).isoformat()
        elif remitter == "annual":
            start = last.replace(month=1, day=1).isoformat()
        elif remitter == "threshold_1":
            start = last.replace(day=1 if last.day == 15 else 16).isoformat()
        elif remitter == "threshold_2":
            start = last.replace(day=1 if last.day == 7 else 8 if last.day == 14 else 15 if last.day == 21 else 22).isoformat()
    return bool(start and end and start <= payday <= end)


def _build(*, scope: Mapping[str, Any], company_ref: str, jurisdiction: Literal["AU", "CA"], as_of: str, runs: Sequence[Mapping[str, Any]], expected_components: Sequence[str] | None, exemptions: Mapping[str, Mapping[str, str]] | None, calendar: Mapping[str, Any] | None, books: Mapping[str, Any] | None, liability_accounts: Sequence[Mapping[str, Any]], unpaid_basis: Mapping[str, Any] | None, fixture_only: bool) -> PayrollTieOut:
    bound = EngineScope.model_validate(dict(scope))
    at = timestamp(as_of, field_name="as_of")
    if jurisdiction not in COMPONENT_KINDS:
        return seal(PayrollTieOut, {"scope": bound.to_dict(), "company_ref": company_ref, "jurisdiction": jurisdiction,
            "as_of": at, "checks": [{"check": "coverage", "subject": "Payroll evidence", "status": "not_comparable",
            "note": f"Payroll tie-out is not supported for {jurisdiction}. No provider evidence was processed."}],
            "source_digests": [], "facts_digest": stable_digest({})}, "report_digest")
    require(bound.currency == {"AU": "AUD", "CA": "CAD"}[jurisdiction], "PAYROLL_JURISDICTION_MISMATCH")
    codes = COMPONENT_KINDS[jurisdiction]
    expected = tuple(expected_components or ())
    require(len(expected) <= 30 and len(set(expected)) == len(expected) and set(expected) <= set(codes), "EXPECTED_COMPONENTS_INVALID")
    exempt = dict(exemptions or {})
    require(len(exempt) <= 500 and all(set(items) <= set(expected) and all(isinstance(reason, str) and 0 < len(reason.strip()) <= 300 for reason in items.values()) for items in exempt.values()), "EXEMPTIONS_INVALID")
    require(len(runs) <= 50 and len({r["run_ref"] for r in runs}) == len(runs), "PAYROLL_RUN_DUPLICATE_OR_LIMIT")
    workers = {w["worker_ref"] for r in runs for w in r["workers"]}
    require(set(exempt) <= workers, "EXEMPT_WORKER_UNKNOWN")
    accounts = [LiabilityAccount.model_validate(r) for r in liability_accounts]
    mapped = [code for a in accounts for code in a.components]
    require(len(accounts) <= 30 and len(set(a.account_ref for a in accounts)) == len(accounts) and len(set(mapped)) == len(mapped) and set(mapped) <= set(codes), "LIABILITY_ACCOUNT_MAP_INVALID")
    checks: list[dict[str, Any]] = []
    digests = [r["source_digest"] for r in runs]
    def add(check: str, subject: str, status: str, note: str, **fields: Any) -> None:
        checks.append(dict(check=check, subject=subject, status=status, note=note, **fields))
    if not runs:
        add("coverage", "Payroll evidence", "not_comparable", PLATFORM_DEPENDENCY if jurisdiction == "CA" else "No complete governed posted payroll observation was supplied.")
    if fixture_only:
        add("coverage", "Provider availability", "not_comparable", PLATFORM_DEPENDENCY + " These figures are synthetic fixture evidence only.")
    if not expected:
        add("deductions", "Expected deductions", "not_comparable", "Confirm applicable components and worker exemptions from payroll configuration; applicability is not inferred from wages or province.")
    basis = UnpaidPayrollBasis.model_validate(unpaid_basis) if unpaid_basis is not None else None
    basis_confirmed = bool(basis and basis.complete_inventory_confirmed and
        basis.confirmed_by_ref.startswith(("owner:", "user:")) and basis.as_of_date.isoformat() <= at[:10] and not fixture_only)
    overdue_components = set()
    rows, cal_digest, calendar_facts = _calendar(calendar, bound, company_ref, jurisdiction)
    if cal_digest:
        digests.append(cal_digest)
    for run in runs:
        # Ask the existing country compiler for the period containing this pay
        # date, then require that exact obligation in the supplied calendar.
        # A cropped/late calendar must not silently select the next period.
        expected_rows = []
        if calendar_facts is not None:
            if jurisdiction == "AU":
                from lightbulb.australia_obligations import compile_australia_obligations
                expanded = compile_australia_obligations(company_ref, start_on=run["payment_date"], facts=calendar_facts, pay_runs=[{"pay_date": run["payment_date"]}])
            else:
                from lightbulb.canada_obligations import compile_canada_obligations
                expanded = compile_canada_obligations(company_ref, start_on=run["payment_date"], horizon_months=1, facts=calendar_facts)
            expected_rows = [row.to_dict() for row in expanded.obligations]
        for code in expected:
            applicable = [w for w in run["workers"] if code not in exempt.get(w["worker_ref"], {})]
            missing = [w for w in applicable if code not in w["components"]]
            zero = [w for w in applicable if w["components"].get(code) == 0]
            status = "not_applicable" if not applicable else "missing" if missing else "not_comparable" if zero else "present"
            add("deductions", code, status, f"{len(missing)} of {len(applicable)} applicable workers lack the component; {len(zero)} reported zero. Only positive observed amounts establish presence; exemptions and rates are not validated.", run_ref=run["run_ref"], component=code)
        totals: dict[str, int] = {}
        for worker in run["workers"]:
            for code, amount in worker["components"].items():
                totals[code] = totals.get(code, 0) + amount
        run["totals"] = totals
        for code, amount in totals.items():
            if not amount:
                continue
            kind = codes.get(code)
            if kind == "superannuation":
                candidates = [r for r in rows if r.get("existing_obligation_ref") == "superannuation:pay:" + run["payment_date"]]
            else:
                unresolved = any(r["kind"] == kind and not r.get("period_end") for r in expected_rows)
                candidates = [] if unresolved else [r for r in expected_rows if r["kind"] == kind and _covers(r, run["payment_date"], jurisdiction)]
                if len(candidates) == 1:
                    wanted = candidates[0]
                    candidates = [r for r in rows if r["obligation_ref"] == wanted["obligation_ref"] and r["due_on"] == wanted["due_on"] and r["period_end"] == wanted["period_end"] and _covers(r, run["payment_date"], jurisdiction)]
            row = candidates[0] if len(candidates) == 1 else None
            scheduled = bool(row and row["status"] == "scheduled" and row.get("due_on") and row["due_on"] >= run["payment_date"])
            status = "scheduled" if scheduled else "not_comparable"
            note = "Matched the existing statutory calendar; no new deadline or payment was created." if scheduled else "No unique confirmed statutory obligation contains this pay date; confirm the remitter/program or calendar coverage."
            if scheduled and row["due_on"] < at[:10]:
                unpaid = basis_confirmed and code in basis.unpaid_components.get(run["run_ref"], ()) and row["due_on"] < basis.as_of_date.isoformat()
                status = "overdue" if unpaid else "not_comparable"
                note = f"Deadline passed; reported unpaid by {basis.confirmed_by_ref} as of {basis.as_of_date}." if unpaid else "Deadline passed; current payment status is unverified."
                if unpaid:
                    overdue_components.add((run["run_ref"], code))
            add("calendar", code, status, note, run_ref=run["run_ref"], component=code, payroll_amount=f"{Decimal(amount) / 100:.2f}", **({"obligation_ref": row["obligation_ref"], "due_on": row["due_on"]} if scheduled else {}))
    snapshot = None
    if books is not None:
        _scope(books, bound)
        snapshot = BooksSnapshot.model_validate(books["document"])
        require((snapshot.company_ref, snapshot.currency) == (company_ref, bound.currency), "BOOKS_SCOPE_MISMATCH")
        require(snapshot.as_of <= at, "BOOKS_FROM_FUTURE")
        require(snapshot.balances_as_at is None or snapshot.balances_as_at <= at, "BOOKS_FROM_FUTURE")
        digests.append(snapshot.snapshot_digest)
    by_ref = {r["run_ref"]: r for r in runs}
    if basis:
        require(set(basis.unpaid_components) <= set(by_ref), "UNPAID_RUN_UNKNOWN")
        for ref, components in basis.unpaid_components.items():
            require(len(set(components)) == len(components) and set(components) <= set(by_ref[ref]["totals"]), "UNPAID_COMPONENT_UNKNOWN")
    if not accounts:
        add("books", "Liability account mapping", "not_comparable", "Confirm the books liability account for each payroll component.")
    known = {c for r in runs for c, amount in r["totals"].items() if amount}
    for code in sorted(known - set(mapped)):
        add("books", code, "not_comparable", "Payroll component has no confirmed liability account mapping.", component=code)
    for account in accounts:
        matching = [] if snapshot is None else [line for line in snapshot.lines if line.account_ref == account.account_ref and line.account_class == "liability"]
        if not basis_confirmed or not snapshot or snapshot.balances_as_at is None or basis.as_of_date.isoformat() != snapshot.balances_as_at[:10] or len(matching) != 1 or not runs or any(r["payment_date"] > basis.as_of_date.isoformat() for r in runs):
            add("books", account.account_ref, "not_comparable", "Need a matching liability account, books balance date and complete human-confirmed unpaid inventory covering these pay runs. A pay-run expense is not a closing liability balance. Synthetic fixtures never prove a books balance.", account_ref=account.account_ref)
            continue
        amount = Decimal(sum(by_ref[ref]["totals"][c] for ref, cs in basis.unpaid_components.items() for c in cs if c in account.components)) / 100
        balance = matching[0].amount
        difference = amount - balance
        overdue = any(c in account.components for _, c in overdue_components)
        status = "differs" if difference else "overdue" if overdue else "tied_on_stated_basis"
        note = f"Exact cents comparison, conditional on {basis.confirmed_by_ref}'s complete inventory as of {basis.as_of_date}; remittances and partial balances are not proved."
        if difference:
            note += f" Differs by {difference:.2f} {bound.currency}."
        if overdue:
            note += " Includes a reported unpaid liability past its deadline."
        add("books", "Payroll liability account " + account.account_ref, status, note, account_ref=account.account_ref, payroll_amount=f"{amount:.2f}", books_amount=f"{balance:.2f}", difference=f"{difference:.2f}")
    facts = {"expected_components": expected, "exemptions": exempt, "liability_accounts": [a.to_dict() for a in accounts], "unpaid_basis": None if basis is None else basis.to_dict()}
    return seal(PayrollTieOut, {"scope": bound.to_dict(), "company_ref": company_ref, "jurisdiction": jurisdiction, "as_of": at, "checks": checks, "source_digests": sorted(set(digests)), "facts_digest": stable_digest(facts), "books_balance_date": None if snapshot is None or snapshot.balances_as_at is None else snapshot.balances_as_at[:10], "unpaid_basis": None if basis is None else basis.to_dict(), "fixture_only": fixture_only, "expected_components": expected, "exemptions": exempt, "liability_accounts": [a.to_dict() for a in accounts]}, "report_digest")


def check_payroll_tie_out(*, scope: Mapping[str, Any], company_ref: str, jurisdiction: Literal["AU", "CA"], as_of: str, payruns: Sequence[Mapping[str, Any]] = (), expected_components: Sequence[str] | None = None, exemptions: Mapping[str, Mapping[str, str]] | None = None, calendar: Mapping[str, Any] | None = None, books: Mapping[str, Any] | None = None, liability_accounts: Sequence[Mapping[str, Any]] = (), unpaid_basis: Mapping[str, Any] | None = None) -> PayrollTieOut:
    """Read-only check; provider data must retain its trusted host scope envelope."""
    bound = EngineScope.model_validate(dict(scope))
    at = timestamp(as_of, field_name="as_of")
    require(len(payruns) <= 50, "PAYROLL_RUN_LIMIT")
    require(jurisdiction != "CA" or not payruns, "CANADA_GOVERNED_PAYROLL_UNAVAILABLE")
    runs = [_observed_run(source, bound, at) for source in payruns] if jurisdiction == "AU" else []
    return _build(scope=scope, company_ref=company_ref, jurisdiction=jurisdiction, as_of=at, runs=runs, expected_components=expected_components, exemptions=exemptions, calendar=calendar, books=books, liability_accounts=liability_accounts, unpaid_basis=unpaid_basis, fixture_only=False)


def preview_canada_payroll_tie_out(*, fixtures: Sequence[Mapping[str, Any]], **kwargs: Any) -> PayrollTieOut:
    """Synthetic contract preview only; this is not a QuickBooks connector read."""
    import re
    require(len(fixtures) <= 50, "PAYROLL_RUN_LIMIT")
    bound = EngineScope.model_validate(kwargs["scope"])
    runs = []
    for fixture in fixtures:
        _scope(fixture, bound)
        raw = detached(fixture["payload"])
        require(set(raw) == {"schema", "fixture_only", "run_ref", "payment_date", "period_end", "workers"} and raw["schema"] == "lightbulb.canada_payroll_fixture.v1" and raw["fixture_only"] is True, "CANADA_FIXTURE_REQUIRED")
        require(bool(re.fullmatch(r"payrun:[0-9a-f]{64}", raw["run_ref"])), "RUN_REF_INVALID")
        require(date.fromisoformat(raw["period_end"]) <= date.fromisoformat(raw["payment_date"]) <= date.fromisoformat(kwargs["as_of"][:10]), "PAYROLL_PERIOD_INVALID")
        require(isinstance(raw["workers"], list) and 0 < len(raw["workers"]) <= 500, "WORKERS_INVALID")
        require(len({r["worker_ref"] for r in raw["workers"]}) == len(raw["workers"]), "WORKERS_DUPLICATE")
        for worker in raw["workers"]:
            require(set(worker) == {"worker_ref", "components"} and bool(re.fullmatch(r"worker:[0-9a-f]{64}", worker["worker_ref"])), "WORKER_REF_INVALID")
            require(set(worker["components"]) <= set(COMPONENT_KINDS["CA"]) and all(type(v) is int and 0 <= v <= 10**14 for v in worker["components"].values()), "COMPONENTS_INVALID")
        runs.append({**raw, "source_digest": stable_digest(raw)})
    return _build(jurisdiction="CA", runs=runs, fixture_only=True, expected_components=kwargs.pop("expected_components", None), exemptions=kwargs.pop("exemptions", None), calendar=kwargs.pop("calendar", None), books=kwargs.pop("books", None), liability_accounts=kwargs.pop("liability_accounts", ()), unpaid_basis=kwargs.pop("unpaid_basis", None), **kwargs)


__all__ = ["PayrollTieOut", "PayrollCheck", "PayrollTieOutError", "LiabilityAccount", "UnpaidPayrollBasis", "check_payroll_tie_out", "preview_canada_payroll_tie_out"]
