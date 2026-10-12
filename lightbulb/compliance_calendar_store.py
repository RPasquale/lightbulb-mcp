"""The compliance calendar kept in the project: every plan an obligation was opened under, so each obligation always reads under its own plan.

A calendar is compiled from things that change with time: today's date (which
periods are in view), the pay runs the company has committed (Australian super
falls on each payday), and the estimates the owner gives.  Its digest changes
with them.  Every obligation is bound to the exact digest of the plan it was
opened under, so an obligation read back under today's plan used to fail
validation and quietly drop out of the calendar: its reservation, lodgement and
payment vanished from the summary and the forecast fell back to estimates.

The calendar is now kept the way the bundle is:

* ``keep_calendar_plan`` keeps every plan the calendar opens obligations under,
  written once under ``plan:<plan digest>`` in the ``compliance_calendar`` engine,
  and moves ``calendar:current`` on by one version with the index of every
  version kept.
* ``calendar_obligations`` reads every persisted obligation (all of them, never a
  first page) and binds each to the plan it was opened under: a kept version, or
  the bundle's own calendar plan.  One that no plan accepts is returned as
  unbound with the reason, never dropped.
* ``adopt_unkept_obligations`` reads obligations opened before plans were kept.
  Their plan is rebuilt the way the console compiled it (the company's
  jurisdiction and facts, from the moment the obligation was opened), and each
  one is migrated onto it through the store's migration fence with a sealed proof
  that names the plan it left.  An obligation whose history the rebuilt plan does
  not accept stays unbound and is reported.
* ``mark_overdue`` moves every obligation past its due date (and the plan's
  grace) to ``overdue`` once, under its own plan, so the exceptions desk opens a
  case for it.

Nothing here reads a provider, lodges or pays anything.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from lightbulb.company_engine_core import detached, parsed, stable_digest, timestamp

CALENDAR_ENGINE = "compliance_calendar"
CALENDAR_CURRENT = "calendar:current"
CALENDAR_PLAN_RECORD_SCHEMA = "lightbulb.compliance_calendar_plan_record.v1"
CALENDAR_POINTER_SCHEMA = "lightbulb.compliance_calendar_pointer.v1"
REBUILT_REASON = "the plan this obligation was opened under was never kept; it is rebuilt from the company's jurisdiction and facts as the calendar stood when the obligation was opened, and the obligation's own history replays under it"


def plan_entity(plan_digest: str) -> str:
    return f"plan:{plan_digest}"


def _record_plan_digest(company_ref: str) -> str:
    # the records' own plan is the company's calendar: one per company, never changing across versions
    return stable_digest({CALENDAR_ENGINE: company_ref})


def _scope(bundle: Any, entity_ref: str) -> dict[str, Any]:
    return dict(bundle.engine_scope(entity_ref))


def kept_versions(store: Any) -> list[dict[str, Any]]:
    """The index of every calendar version kept, oldest first (empty when none is)."""

    record = store.get(CALENDAR_ENGINE, CALENDAR_CURRENT)
    if record is None:
        return []
    versions = dict(record["state"]).get("versions")
    if not isinstance(versions, (list, tuple)) or not versions or any(
        not isinstance(row, Mapping) or not isinstance(row.get("plan_digest"), str)
        or len(row["plan_digest"]) != 64 or type(row.get("version")) is not int
        or row["version"] < 1 for row in versions
    ):
        raise ValueError("CALENDAR_RECORD_INVALID: malformed calendar version index")
    return [dict(row) for row in versions]


_VERIFIED_PLANS: dict[str, Any] = {}


def kept_plan(store: Any, plan_digest: str) -> Any | None:
    """The kept calendar plan with this digest, re-verified; ``None`` when no such version is kept.

    A kept plan is written once under its own digest, so once one has verified under that digest it is the same
    plan wherever it is read again.
    """

    from lightbulb.compliance_calendar import ComplianceCalendarPlan

    record = store.get(CALENDAR_ENGINE, plan_entity(plan_digest))
    if record is None:
        return None
    state = dict(record["state"])
    if state.get("schema") != CALENDAR_PLAN_RECORD_SCHEMA or state.get("state_digest") != plan_digest:
        raise ValueError("CALENDAR_RECORD_INVALID: the kept calendar record has an unknown shape or names another plan")
    verified = _VERIFIED_PLANS.get(plan_digest)
    if verified is not None:
        return verified
    plan = ComplianceCalendarPlan.model_validate(dict(state["plan"]))
    if plan.plan_digest != plan_digest:
        raise ValueError("CALENDAR_RECORD_INVALID: the kept calendar plan does not match the digest it is kept under")
    if len(_VERIFIED_PLANS) >= 512:
        _VERIFIED_PLANS.clear()
    _VERIFIED_PLANS[plan_digest] = plan
    return plan


def calendar_content_digest(plan: Any) -> str:
    """Compare facts and obligation content without retaining a new version every day."""
    raw = plan.to_dict()
    raw.pop("plan_digest", None)
    for name in ("canada_calendar", "australia_calendar"):
        calendar = raw.get(name)
        if calendar is not None:
            for key in ("calendar_digest", "start_on", "end_on"):
                calendar.pop(key, None)
    return stable_digest(raw)


def current_scoped_calendar_plan(store: Any, bundle: Any) -> Any | None:
    """Read the current calendar only after binding pointer and record to this bundle."""
    pointer = store.get(CALENDAR_ENGINE, CALENDAR_CURRENT)
    if pointer is None:
        return None
    state = dict(pointer["state"])
    if dict(state.get("scope") or {}) != _scope(bundle, CALENDAR_CURRENT):
        raise ValueError("SCOPE_MISMATCH: the calendar pointer belongs to another execution scope")
    kept_versions(store)  # malformed version indexes fail before any adoption or write
    digest = str(state.get("state_digest") or "")
    record = store.get(CALENDAR_ENGINE, plan_entity(digest))
    if record is None:
        raise ValueError("CALENDAR_RECORD_INVALID: the current plan is missing")
    if dict(dict(record["state"]).get("scope") or {}) != _scope(bundle, plan_entity(digest)):
        raise ValueError("SCOPE_MISMATCH: the calendar plan belongs to another execution scope")
    plan = kept_plan(store, digest)
    if plan is None or plan.company_ref != bundle.company_ref:
        raise ValueError("SCOPE_MISMATCH: the calendar belongs to another company")
    return plan


def keep_calendar_plan(store: Any, bundle: Any, plan: Any, *, as_of: str, opened: int = 0, reason: str = "obligations opened") -> dict[str, Any]:
    """Keep ``plan`` as a calendar version (written once) and make it the current one; keeping a version already kept only moves the pointer."""

    from lightbulb.compliance_calendar import ComplianceCalendarPlan

    parsed_plan = plan if isinstance(plan, ComplianceCalendarPlan) else ComplianceCalendarPlan.model_validate(dict(detached(plan)))
    if parsed_plan.company_ref != bundle.company_ref:
        raise ValueError("SCOPE_MISMATCH: the calendar belongs to another company")
    at = timestamp(as_of, field_name="as_of")
    record_plan = _record_plan_digest(bundle.company_ref)
    pointer = store.get(CALENDAR_ENGINE, CALENDAR_CURRENT)
    versions = kept_versions(store)
    entity = plan_entity(parsed_plan.plan_digest)
    known = next((row for row in versions if row.get("plan_digest") == parsed_plan.plan_digest), None)
    if known is None:
        version = len(versions) + 1
        document = {"schema": CALENDAR_PLAN_RECORD_SCHEMA, "status": "kept", "plan_digest": record_plan, "version": 1, "state_digest": parsed_plan.plan_digest, "scope": _scope(bundle, entity), "as_of": at, "calendar_version": version, "reason": reason[:300], "plan": parsed_plan.to_dict()}
        store.put(CALENDAR_ENGINE, entity, document, expected_version=None, expected_state_digest=None)
        versions = [*versions, {"version": version, "plan_digest": parsed_plan.plan_digest, "as_of": at, "opened": int(opened), "reason": reason[:300]}]
    else:
        version = int(known["version"])
    if pointer is not None and dict(pointer["state"]).get("state_digest") == parsed_plan.plan_digest:
        return {"entity_ref": entity, "calendar_version": version, "plan_digest": parsed_plan.plan_digest, "kept_now": known is None}
    document = {"schema": CALENDAR_POINTER_SCHEMA, "status": "current", "plan_digest": record_plan, "version": 1 if pointer is None else int(pointer["version"]) + 1, "state_digest": parsed_plan.plan_digest, "scope": _scope(bundle, CALENDAR_CURRENT), "as_of": at, "calendar_version": version, "versions": versions}
    store.put(CALENDAR_ENGINE, CALENDAR_CURRENT, document, expected_version=None if pointer is None else int(pointer["version"]), expected_state_digest=None if pointer is None else str(pointer["state_digest"]))
    return {"entity_ref": entity, "calendar_version": version, "plan_digest": parsed_plan.plan_digest, "kept_now": known is None}


@dataclass
class CalendarObligations:
    """Every persisted obligation, each bound to the plan it was opened under, and the ones no plan accepts (with why)."""

    bound: list[tuple[Any, Any]] = field(default_factory=list)
    unbound: list[dict[str, Any]] = field(default_factory=list)

    def plans(self) -> dict[str, Any]:
        return {plan.plan_digest: plan for plan, _ in self.bound}

    def by_ref(self) -> dict[str, tuple[Any, Any]]:
        return {str(state.ledger.obligation_ref): (plan, state) for plan, state in self.bound}


def _bundle_plan(bundle: Any) -> Any | None:
    from lightbulb.compliance_calendar import ComplianceCalendarPlan

    raw = dict(getattr(bundle, "supporting_plans", {}) or {}).get("compliance_obligation")
    return None if raw is None else ComplianceCalendarPlan.model_validate(dict(detached(raw)))


def calendar_obligations(store: Any, bundle: Any) -> CalendarObligations:
    """Bind every persisted obligation to its own plan: a kept calendar version, else the bundle's calendar plan; anything else is unbound, with the reason."""

    from lightbulb.company_engine_store import complete_engine_states
    from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE

    plans: dict[str, Any] = {}
    bundle_plan = _bundle_plan(bundle)
    if bundle_plan is not None:
        plans[bundle_plan.plan_digest] = bundle_plan
    out = CalendarObligations()
    for record in complete_engine_states(store, engine=COMPLIANCE_KIND):
        raw = dict(record["state"])
        digest = str(raw.get("plan_digest") or record.get("plan_digest") or "")
        plan = plans.get(digest)
        if plan is None:
            try:
                plan = kept_plan(store, digest)
            except ValueError as exc:
                out.unbound.append(_unbound(record, f"CALENDAR_RECORD_INVALID: {exc}"))
                continue
            if plan is not None:
                plans[digest] = plan
        if plan is None:
            out.unbound.append(_unbound(record, "PLAN_NOT_KEPT: the plan this obligation was opened under is not kept in the project and is not the bundle's"))
            continue
        try:
            state = COMPLIANCE_LIFECYCLE.State.model_validate(raw, context={COMPLIANCE_LIFECYCLE.plan_context_key: plan})
        except ValueError as exc:
            out.unbound.append(_unbound(record, f"STATE_DOES_NOT_REPLAY: {str(exc).splitlines()[0][:240]}"))
            continue
        if str(state.scope.entity_ref) != str(record.get("entity_ref")) or any(getattr(state.scope, key) != bundle.engine_scope(str(state.scope.entity_ref))[key] for key in ("tenant_ref", "company_ref", "project_ref", "project_id", "currency")):
            out.unbound.append(_unbound(record, "SCOPE_MISMATCH: the obligation is outside this company's scope"))
            continue
        out.bound.append((plan, state))
    return out


def _unbound(record: Mapping[str, Any], reason: str) -> dict[str, Any]:
    raw = dict(record.get("state") or {})
    ledger = dict(raw.get("ledger") or {})
    return {"engine": "compliance_obligation", "entity_ref": str(record.get("entity_ref")), "obligation_ref": str(ledger.get("obligation_ref") or record.get("entity_ref")), "kind": ledger.get("kind"), "due_at": ledger.get("due_at"), "status": str(raw.get("status") or record.get("status") or ""), "plan_digest": str(raw.get("plan_digest") or record.get("plan_digest") or ""), "state_digest": str(raw.get("state_digest") or record.get("state_digest") or ""), "reason": reason[:300]}


def adopt_unkept_obligations(store: Any, bundle: Any, unbound: Sequence[Mapping[str, Any]], *, rebuild: Any, migrated_at: str, actor_ref: str) -> list[dict[str, Any]]:
    """Migrate each obligation whose plan was never kept onto its rebuilt plan, keep that plan, and report what happened to each.

    ``rebuild(opened_at)`` compiles the calendar as the console would have at that
    moment.  Each migration goes through the store's migration fence with the
    sealed proof; an obligation whose history the rebuilt plan refuses is left
    unbound and reported with the refusal.
    """

    from lightbulb.company_plan_migration import MigrationRefused, rebind_state
    from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE

    outcomes: list[dict[str, Any]] = []
    for row in unbound:
        if not str(row.get("reason", "")).startswith("PLAN_NOT_KEPT"):
            continue
        record = store.get(COMPLIANCE_KIND, str(row["entity_ref"]))
        if record is None:
            continue
        raw = dict(record["state"])
        try:
            opened_at = str(dict(raw["transition_history"][0]["command"])["occurred_at"])
            plan = rebuild(opened_at)
            candidate = plan.obligation(str(row["obligation_ref"]))
            if candidate is None:
                raise MigrationRefused("OBLIGATION_NOT_IN_REBUILT_PLAN", f"{row['obligation_ref']} is not on the calendar rebuilt from {opened_at[:10]}")
            original_due = dict(raw.get("ledger") or {}).get("due_at")
            if original_due and candidate.due_at > original_due:
                raise MigrationRefused("ADOPTION_WOULD_POSTPONE", "rebuilding an unkept plan cannot postpone its persisted deadline")
            if plan.plan_digest == str(raw.get("plan_digest")):
                # rebuilt to the byte: the obligation reads under its own plan once it is kept, and nothing is migrated
                COMPLIANCE_LIFECYCLE.bind(plan, raw)
                keep_calendar_plan(store, bundle, plan, as_of=migrated_at, reason="rebuilt exactly for an obligation whose plan was never kept")
                outcomes.append({**dict(row), "adopted": True, "to_plan_digest": plan.plan_digest, "migration_digest": None})
                continue
            result = rebind_state(COMPLIANCE_LIFECYCLE, state=raw, to_plan=plan, migrated_at=migrated_at, actor_ref=actor_ref, reason=REBUILT_REASON)
            keep_calendar_plan(store, bundle, plan, as_of=migrated_at, reason="rebuilt for an obligation whose plan was never kept")
            store.migrate(COMPLIANCE_KIND, str(row["entity_ref"]), detached(result.state), migration=result.migration.to_dict())
            outcomes.append({**dict(row), "adopted": True, "to_plan_digest": plan.plan_digest, "migration_digest": result.migration.migration_digest})
        except (MigrationRefused, ValueError, KeyError, IndexError) as exc:
            outcomes.append({**dict(row), "adopted": False, "refusal": f"{getattr(exc, 'code', type(exc).__name__)}: {str(exc)[:240]}"})
    return outcomes


def retain_payroll_periods(plan: Any, obligations: CalendarObligations) -> Any:
    """Keep a saved aggregate when an accelerated remitter splits its period.

    Its full liability moves to the earliest confirmed date within that period.
    Suppress overlapping new estimates so the same liability is not counted twice.
    """
    if plan.canada_calendar is None:
        return plan
    from lightbulb.compliance_calendar import ComplianceCalendarPlan
    from lightbulb.company_engine_core import seal
    raw = plan.to_dict()
    changed = False
    for own, state in obligations.bound:
        if state.status in ("paid", "waived"):
            continue
        mine = own.obligation(str(state.ledger.obligation_ref))
        current = plan.obligation(str(state.ledger.obligation_ref))
        if mine is None or current is None or mine.kind != "payg_withholding" or own.jurisdiction != "CA":
            continue
        if not (mine.period_start < current.period_start and mine.period_end == current.period_end):
            continue
        dates = [row["due_on"] for row in plan.canada_calendar["obligations"] if row["kind"] == "payroll" and row["status"] == "scheduled" and row["due_on"] and row["period_end"] and mine.period_start[:10] <= row["period_end"] < mine.period_end[:10]]
        if not dates:
            continue
        due = (parsed(min(dates) + "T00:00:00Z") + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        due = min(due, mine.due_at)
        raw["schedule"] = [row for row in raw["schedule"] if not (row["kind"] == "payg_withholding" and mine.period_start <= row["period_start"] and row["period_end"] <= mine.period_end)]
        raw["schedule"].append({**mine.to_dict(), "due_at": due})
        changed = True
    if not changed:
        return plan
    raw["schedule"].sort(key=lambda row: (row["due_at"], row["obligation_ref"]))
    return seal(ComplianceCalendarPlan, raw, "plan_digest")


def deadline_missing_facts(plan: Any, item: Any) -> tuple[str, ...]:
    """Facts whose withdrawal invalidates a saved deadline, independent of horizon."""
    if plan.australia_calendar is not None and item.kind == "gst_bas":
        if (plan.australia_calendar.get("facts") or {}).get("gst_reporting") is None:
            return ("gst_reporting",)
    if plan.canada_calendar is not None:
        from lightbulb.canada_obligations import CanadaCalendarFacts, compile_canada_obligations, remitter_assignments
        facts = CanadaCalendarFacts.model_validate(plan.canada_calendar["facts"])
        period = (parsed(item.period_end) - timedelta(days=1)).date().isoformat()
        if item.kind == "income_tax_instalment" and (plan.calendar_facts or {}).get("instalments") == "quarterly":
            from calendar import monthrange
            due_month = parsed(item.period_end)
            period = due_month.date().replace(day=min(facts.fiscal_year_end_day or 31, monthrange(due_month.year, due_month.month)[1])).isoformat()
        if item.kind == "payg_withholding":
            year = period[:4]
            assignments, conflicts = remitter_assignments(facts)
            if year in conflicts:
                return (f"conflicting explicit remitter assignments for {year}",)
            if year not in assignments:
                return (f"remitters_by_year.{year} or remitter/AMWA with remitter_year {year}",)
        kinds = {"gst_bas": "gst_hst", "annual_return": "corporate_balance", "income_tax_instalment": "corporate_instalment"}
        if item.kind in kinds:
            kind = kinds[item.kind]
            if item.kind == "gst_bas" and facts.entity_type == "sole_proprietor" and facts.gst_reporting == "annual":
                kind = "gst_payment"
            # Ask the real compiler about the saved period, even after it has
            # left today's horizon. Never substitute the forecast's default
            # fiscal month for a withdrawn statutory fact.
            calendar = compile_canada_obligations(plan.company_ref,
                start_on=max(period, "2026-01-01"), horizon_months=7,
                facts=facts.to_dict(), fiscal_year_end_month=facts.fiscal_year_end_month,
                has_payroll=False)
            relevant = [row for row in calendar.obligations if row.kind == kind
                        and row.period_end in (None, period)]
            if any(row.period_end == period and row.status == "scheduled" and row.due_on for row in relevant):
                return ()
            missing = tuple(sorted({row.basis for row in relevant if row.status == "needs_confirmation"}))
            if missing:
                return missing
    return ()


def restore_known_deadlines(plan: Any, obligations: CalendarObligations, *, rebuild: Any) -> Any:
    """Rebuild saved uncertainty or changed AU extensions outside the window."""
    from lightbulb.compliance_calendar import ComplianceCalendarPlan
    from lightbulb.company_engine_core import seal
    raw, rebuilt, changed = plan.to_dict(), {}, False
    for own, state in obligations.bound:
        item = own.obligation(str(state.ledger.obligation_ref))
        if state.status in ("paid", "waived") or item is None:
            continue
        extension_facts = ("gst_reporting", "bas_program", "bas_extension_eligible", "registered_agent", "instalments", "december_monthly_bas_concession")
        previous = (own.australia_calendar or {}).get("facts") or {}
        current_facts = (plan.australia_calendar or {}).get("facts") or {}
        changed_extension = (own.australia_calendar is not None and plan.australia_calendar is not None
            and item.kind in ("gst_bas", "payg_withholding", "income_tax_instalment")
            and any(previous.get(key) != current_facts.get(key) for key in extension_facts))
        if item.deadline_status != "unknown" and not changed_extension:
            continue
        if plan.obligation(item.obligation_ref) is not None or deadline_missing_facts(plan, item):
            continue
        # An annual filing is due after its entire year has ended; rebuilding
        # only from the year's start can exclude its deadline from the horizon.
        rebuild_at = item.period_start if item.kind == "payg_withholding" else item.period_end
        if rebuild_at not in rebuilt:
            rebuilt[rebuild_at] = rebuild(rebuild_at)
        historical = retain_payroll_periods(rebuilt[rebuild_at], CalendarObligations(bound=[(own, state)]))
        candidate = historical.obligation(item.obligation_ref)
        if candidate is None or candidate.deadline_status is not None or (candidate.period_start, candidate.period_end) != (item.period_start, item.period_end):
            continue
        name = "canada_calendar" if plan.jurisdiction == "CA" else "australia_calendar"
        source, current = getattr(historical, name, None), raw.get(name)
        if not source or not current or source["facts"] != current["facts"]:
            continue
        # Changed extension facts can bring a saved deadline before today's
        # horizon. Rebuild that same period before correcting or judging it late.
        # Keep the exact statutory evidence that supports this historical period;
        # do not import unrelated old schedules or re-open their liabilities.
        evidence = [row for row in source["obligations"] if row["status"] == "scheduled" and row.get("period_end") and item.period_start[:10] <= row["period_end"] < item.period_end[:10]]
        if item.kind == "income_tax_instalment":
            # Fiscal instalments cover year-to-date through the start of their
            # due month, while the statutory row names its actual due day.
            from calendar import monthrange
            due_month = parsed(item.period_end)
            facts = current.get("facts") or {}
            period = due_month.date().replace(day=min(facts.get("fiscal_year_end_day") or 31, monthrange(due_month.year, due_month.month)[1])).isoformat()
            evidence.extend(row for row in source["obligations"] if row["kind"] == "corporate_instalment" and row["status"] == "scheduled" and row.get("period_end") == period)
        if not evidence:
            continue
        by_ref = {row["obligation_ref"]: row for row in current["obligations"]}
        by_ref.update({row["obligation_ref"]: row for row in evidence})
        current["obligations"] = sorted(by_ref.values(), key=lambda row: (row.get("due_on") or "9999", row["obligation_ref"]))
        current["start_on"] = min(current["start_on"], source["start_on"])
        if name == "canada_calendar":
            from lightbulb.canada_obligations import CanadaObligationsCalendar as Calendar
        else:
            from lightbulb.australia_obligations import AustraliaObligationsCalendar as Calendar
        raw[name] = seal(Calendar, current, "calendar_digest").to_dict()
        raw["schedule"].append({**candidate.to_dict(), "estimated_amount": str(item.estimated_amount)})
        changed = True
    if not changed:
        return plan
    raw["schedule"].sort(key=lambda row: (row["due_at"], row["obligation_ref"]))
    return seal(ComplianceCalendarPlan, raw, "plan_digest")


def retain_uncertain_deadlines(plan: Any, obligations: CalendarObligations) -> Any:
    """Keep liability/history when facts disappear, with an explicitly unknown date.

    The old marker remains solely to replay the retained history. Consumers must
    use deadline_status; no overdue claim or dated outflow can use that marker.
    """
    from lightbulb.compliance_calendar import ComplianceCalendarPlan
    from lightbulb.company_engine_core import seal
    raw = plan.to_dict()
    changed = False
    for own, state in obligations.bound:
        if state.status in ("paid", "waived"):
            continue
        item = own.obligation(str(state.ledger.obligation_ref))
        if item is None:
            continue
        missing = deadline_missing_facts(plan, item)
        if not missing:
            continue
        raw["schedule"] = [row for row in raw["schedule"] if row["obligation_ref"] != item.obligation_ref]
        raw["schedule"].append({**item.to_dict(), "deadline_status": "unknown", "deadline_missing_facts": list(missing)})
        changed = True
    if not changed:
        return plan
    raw["schedule"].sort(key=lambda row: (row["due_at"], row["obligation_ref"]))
    return seal(ComplianceCalendarPlan, raw, "plan_digest")


CORRECTED_REASON = "the statutory rule or confirmed facts for this obligation changed; the obligation follows the calendar's current rule and deadline certainty"


def follow_corrected_rules(store: Any, bundle: Any, obligations: CalendarObligations, plan: Any, *, migrated_at: str, actor_ref: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Move each open obligation whose own plan dates its period differently from ``plan`` onto ``plan``, with a proof.

    Corrections keep the obligation, kind and period; later dates require confirmed statutory evidence. An
    obligation whose period the current rules no longer have (a company reporting monthly where it
    reported quarterly) keeps its own plan, period and date until it is paid, and is returned as
    superseded so the owner sees it; one whose history the corrected date refuses (marked overdue
    before a date that moved later) stays where it is, with the refusal.
    """

    from lightbulb.company_plan_migration import MigrationRefused, migrate_state
    from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE

    moved: list[dict[str, Any]] = []
    superseded: list[dict[str, Any]] = []
    for index, (own, state) in enumerate(list(obligations.bound)):
        if own.plan_digest == plan.plan_digest or state.status in ("paid", "waived"):
            continue
        ref = str(state.ledger.obligation_ref)
        mine, current = own.obligation(ref), plan.obligation(ref)
        if mine is None or current is None or current.projected:
            continue
        if (mine.kind, mine.period_start, mine.period_end) != (current.kind, current.period_start, current.period_end):
            superseded.append({"obligation_ref": ref, "kind": mine.kind, "period_start": mine.period_start, "period_end": mine.period_end, "due_at": mine.due_at, "current_rule": {"period_start": current.period_start, "period_end": current.period_end, "due_at": current.due_at}})
            continue
        if (current.due_at, current.deadline_status, current.deadline_missing_facts) == (mine.due_at, mine.deadline_status, mine.deadline_missing_facts):
            continue
        if current.kind == "payg_withholding" and own.jurisdiction == "CA" and current.due_at > mine.due_at:
            if (own.calendar_facts or {}).get("withholder") != (plan.calendar_facts or {}).get("withholder"):
                continue  # an aggregate's remitter change cannot postpone its liability
        statutory_calendar = plan.canada_calendar or plan.australia_calendar
        if statutory_calendar is not None and current.deadline_status is None:
            from datetime import timedelta
            from lightbulb.company_engine_core import parsed
            kinds = {"gst_bas": "gst_hst", "payg_withholding": "payroll", "income_tax_instalment": "corporate_instalment", "annual_return": "corporate_balance"}
            if plan.australia_calendar is not None:
                kinds = {"gst_bas": "bas", "payg_withholding": "payg_withholding", "income_tax_instalment": "income_tax_instalment", "annual_return": "company_tax_balance"}
            facts = statutory_calendar.get("facts") or {}
            if facts.get("entity_type") == "sole_proprietor" and facts.get("gst_reporting") == "annual":
                kinds["gst_bas"] = "gst_payment"
            period = (parsed(current.period_end) - timedelta(days=1)).date().isoformat()
            if current.kind == "income_tax_instalment" and plan.jurisdiction == "CA" and (plan.calendar_facts or {}).get("instalments") == "quarterly":
                from calendar import monthrange
                due_month = parsed(current.period_end)
                facts = plan.canada_calendar.get("facts") or {}
                period = due_month.date().replace(day=min(facts.get("fiscal_year_end_day") or 31, monthrange(due_month.year, due_month.month)[1])).isoformat()
            confirmed = [row for row in statutory_calendar["obligations"] if row["status"] == "scheduled" and row["due_on"] and (row.get("existing_obligation_ref") == ref or row["kind"] == kinds.get(current.kind) and row["period_end"] == period)]
            if current.kind == "payg_withholding" and plan.canada_calendar is not None:
                confirmed = [row for row in statutory_calendar["obligations"] if row["kind"] == "payroll" and row["status"] == "scheduled" and row["due_on"] and row["period_end"] and current.period_start[:10] <= row["period_end"] < current.period_end[:10] and row.get("remitter_basis") == (plan.calendar_facts or {}).get("withholder")]
            due_on = (parsed(current.due_at) - timedelta(days=1)).date().isoformat()
            supported = bool(confirmed) and due_on == min(row["due_on"] for row in confirmed)
            if not supported and plan.australia_calendar is not None and current.due_at < mine.due_at:
                candidates = [row for row in statutory_calendar["obligations"] if row["kind"] == kinds.get(current.kind) and row["period_end"] == period and row["due_on"] == due_on and row.get("missing_facts")]
                supported = len(candidates) == 1
                # Removing facts that supported a saved extension must retract it.
                # Only a prior confirmed date for this exact period qualifies;
                # the same-period and earlier-only guards above still apply.
                previous = own.australia_calendar or {}
                prior_facts = previous.get("facts") or {}
                extension_facts = ("gst_reporting", "bas_program", "bas_extension_eligible", "registered_agent", "instalments", "december_monthly_bas_concession")
                withdrawn = any(prior_facts.get(key) is not None and facts.get(key) is None for key in extension_facts)
                prior_due = (parsed(mine.due_at) - timedelta(days=1)).date().isoformat()
                prior_rows = [row for row in previous.get("obligations", ()) if row["kind"] == kinds.get(current.kind) and row["period_end"] == period and row["status"] == "scheduled" and row["due_on"] == prior_due]
                supported = supported or (current.kind in ("gst_bas", "payg_withholding", "income_tax_instalment") and withdrawn and len(prior_rows) == 1)
            if not supported:
                continue
        try:
            result = migrate_state(COMPLIANCE_LIFECYCLE, state=state.to_dict(), from_plan=own, to_plan=plan, migrated_at=migrated_at, actor_ref=actor_ref, reason=CORRECTED_REASON)
            keep_calendar_plan(store, bundle, plan, as_of=migrated_at, reason="a statutory rule was corrected")
            store.migrate(COMPLIANCE_KIND, str(state.scope.entity_ref), detached(result.state), migration=result.migration.to_dict())
            obligations.bound[index] = (plan, COMPLIANCE_LIFECYCLE.bind(plan, detached(result.state))[1])
            moved.append({"obligation_ref": ref, "from_due_at": mine.due_at, "to_due_at": current.due_at, "migration_digest": result.migration.migration_digest})
        except (MigrationRefused, ValueError) as exc:
            moved.append({"obligation_ref": ref, "from_due_at": mine.due_at, "to_due_at": current.due_at, "refusal": f"{getattr(exc, 'code', type(exc).__name__)}: {str(exc)[:240]}"})
    return moved, superseded


OVERDUE_FROM: frozenset[str] = frozenset({"scheduled", "reserved", "lodged"})


def mark_overdue(store: Any, bundle: Any, obligations: CalendarObligations, *, now: str, actor_ref: str) -> list[dict[str, Any]]:
    """Move every obligation past its due date and the plan's grace to ``overdue``, once and under its own plan; returns what moved (and what was refused, with the code)."""

    from lightbulb.company_engine_store import EngineRuntime
    from lightbulb.compliance_calendar import COMPLIANCE_KIND, COMPLIANCE_LIFECYCLE, advance_obligation, obligation_deadline

    at = timestamp(now, field_name="now")
    moved: list[dict[str, Any]] = []
    for index, (plan, state) in enumerate(list(obligations.bound)):
        ledger = state.ledger
        if state.status not in OVERDUE_FROM or ledger.due_at is None or ledger.overdue_since is not None or ledger.deadline_status == "unknown":
            continue
        # the deadline still owed: the return's, when it falls before the payment and neither is done
        deadline = obligation_deadline(plan.obligation(str(ledger.obligation_ref)), state.status, ledger)
        if parsed(at) <= parsed(deadline) + timedelta(days=plan.overdue_grace_days):
            continue
        if parsed(at) < parsed(state.transition_history[-1].command.occurred_at):
            continue
        runtime = EngineRuntime(spec=COMPLIANCE_LIFECYCLE, engine=COMPLIANCE_KIND, plan=plan, store=store, advance=advance_obligation)
        ref = str(state.scope.entity_ref)
        command = runtime.command(state, event="mark_overdue", transition_ref=f"overdue:{ref}", idempotency_key=f"overdue:{ref}", occurred_at=at, actor_ref=actor_ref, receipt={"evidence_refs": [f"due:{deadline[:10]}"]})
        outcome = runtime.advance_and_persist(ref, command)
        if outcome.persisted:
            updated = COMPLIANCE_LIFECYCLE.State.model_validate(dict(outcome.record["state"]), context={COMPLIANCE_LIFECYCLE.plan_context_key: plan})
            obligations.bound[index] = (plan, updated)
            moved.append({"obligation_ref": str(ledger.obligation_ref), "due_at": ledger.due_at, "from": state.status, "days_late": updated.ledger.days_late, **({"lodgement_due_at": deadline} if deadline != str(ledger.due_at) else {})})
        else:
            moved.append({"obligation_ref": str(ledger.obligation_ref), "due_at": ledger.due_at, "from": state.status, "refused": outcome.result.receipt.rejection_code})
    return moved


__all__ = ["CALENDAR_CURRENT", "CALENDAR_ENGINE", "CALENDAR_PLAN_RECORD_SCHEMA", "CALENDAR_POINTER_SCHEMA", "CORRECTED_REASON", "CalendarObligations", "OVERDUE_FROM", "REBUILT_REASON", "adopt_unkept_obligations", "calendar_obligations", "follow_corrected_rules", "keep_calendar_plan", "kept_plan", "kept_versions", "mark_overdue", "plan_entity"]
