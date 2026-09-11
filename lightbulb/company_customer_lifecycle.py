"""Event-triggered enrollment and outcome observation on the existing sales host."""

from datetime import timedelta
from typing import Literal
from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest
from lightbulb.pipeline_engine_loop import ProspectFacts
from lightbulb.company_customer_events import CompanyCustomerEvents, require
from lightbulb.company_customer_crm import CustomerCrmSource
from lightbulb.company_customer_fast_intake import CustomerFastIntakePolicy
from lightbulb.company_customer_experiments import CustomerLifecycleExperiment, CompanyCustomerExperiments
from lightbulb.customer_outcome_templates import CustomerOutcomeTrial, trial_stop_reason


class CustomerLifecycleEnrollment(StrictModel):
    enrollment_ref: OpaqueRef
    binding_ref: OpaqueRef
    goal: Literal["activation", "expansion", "inbound", "renewal"]
    facts: ProspectFacts
    facts_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    required_source_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)
    retention_case_ref: OpaqueRef | None = None
    renewal_invoice_ref: OpaqueRef | None = None
    renewal_inactivity_days: int = Field(default=7, ge=1, le=90, strict=True)
    activation_delay_hours: int = Field(default=24, ge=1, le=720, strict=True)
    max_source_age_seconds: int = Field(default=172800, ge=60, le=604800, strict=True)
    trial_days: int = Field(default=14, ge=1, le=90, strict=True)
    max_touches: int = Field(default=3, ge=1, le=10, strict=True)


class CustomerLifecycleConfiguration(StrictModel):
    crm_sources: tuple[CustomerCrmSource, ...] = Field(default=(), max_length=20)
    trial: CustomerOutcomeTrial | None = None
    fast_intake: CustomerFastIntakePolicy | None = None
    experiments: tuple[CustomerLifecycleExperiment, ...] = Field(default=(), max_length=20)
    enrollments: tuple[CustomerLifecycleEnrollment, ...] = Field(default=(), max_length=100)

    def validate_bindings(self, sales, sources):
        require(
            self.trial is None or len(self.enrollments) <= self.trial.max_enrollments,
            "CUSTOMER_TRIAL_COHORT_INVALID",
        )
        if self.fast_intake is not None:
            accounts = {s.connector_account_ref for s in sources if s.kind == "invoice_health"}
            require(set(self.fast_intake.webhook_connector_refs) <= accounts, "CUSTOMER_WEBHOOK_INVOICE_SOURCE_REQUIRED")
            require(len(set(self.fast_intake.webhook_connector_refs)) == len(self.fast_intake.webhook_connector_refs), "CUSTOMER_WEBHOOK_BINDING_DUPLICATED")
        refs = [row.binding_ref for row in self.enrollments]
        require(len(refs) == len(set(refs)), "CUSTOMER_BINDING_DUPLICATED")
        require(
            len({r.enrollment_ref for r in self.enrollments}) == len(self.enrollments),
            "CUSTOMER_ENROLLMENT_DUPLICATED",
        )
        bindings = {b.binding_ref: b for b in sales.all_bindings()}
        source_map = {
            s.source_ref: s
            for s in (*sources, *self.crm_sources)
            if s.kind in {"customer_events", "crm_inbound"}
        }
        require(
            len({s.source_ref for s in (*sources, *self.crm_sources)})
            == len(sources) + len(self.crm_sources),
            "CUSTOMER_SOURCE_DUPLICATED",
        )
        for row in self.enrollments:
            require(row.binding_ref in bindings, "CUSTOMER_SALES_BINDING_REQUIRED")
            binding = bindings[row.binding_ref]
            purpose = {
                "inbound": "acquisition",
                "activation": "activation",
                "expansion": "expansion",
                "renewal": "renewal",
            }[row.goal]
            require(
                binding.purpose == purpose
                and (row.facts.account_ref, row.facts.prospect_ref)
                == (binding.account_ref, binding.prospect_ref),
                "CUSTOMER_ENROLLMENT_BINDING_MISMATCH",
            )
            require(
                set(row.required_source_refs) <= source_map.keys(), "CUSTOMER_EVENT_SOURCE_REQUIRED"
            )
            selected = [source_map[ref] for ref in row.required_source_refs]
            require(
                all(binding.account_ref in source.identity_links.values() for source in selected),
                "CUSTOMER_SOURCE_IDENTITY_REQUIRED",
            )
            kinds = {
                mapping["kind"] for source in selected for mapping in source.event_bindings.values()
            }
            triggers = {
                "activation": {"signed_up"},
                "expansion": {"capacity_reached", "upgrade_requested"},
                "inbound": {"demo_requested", "inquiry_received"},
                "renewal": {"renewal_due"},
            }[row.goal]
            require(bool(kinds & triggers), "CUSTOMER_TRIGGER_SOURCE_REQUIRED")
            success = {
                "activation": "activated",
                "expansion": "expanded",
                "inbound": None,
                "renewal": None,
            }[row.goal]
            require(success is None or success in kinds, "CUSTOMER_OUTCOME_SOURCE_REQUIRED")
            if row.goal == "renewal":
                require(
                    "product_used" in kinds
                    and row.retention_case_ref is not None
                    and row.renewal_invoice_ref is not None
                    and any(
                        source.kind == "invoice_health"
                        and binding.account_ref in source.identity_links.values()
                        for source in sources
                    ),
                    "CUSTOMER_RENEWAL_BINDING_REQUIRED",
                )
            else:
                require(
                    row.retention_case_ref is None and row.renewal_invoice_ref is None,
                    "CUSTOMER_RENEWAL_BINDING_UNEXPECTED",
                )
        return self


class CompanyCustomerLifecycle:
    def __init__(self, sales, configuration=None):
        self.sales = sales
        self.configuration = CustomerLifecycleConfiguration.model_validate(
            configuration or {}
        ).validate_bindings(sales.configuration, sales.sources)
        self.events = CompanyCustomerEvents(sales.runner, sales.gateway)
        self.enrollments = {r.binding_ref: r for r in self.configuration.enrollments}
        self.experiments = CompanyCustomerExperiments(self, self.configuration.experiments)

    def execution_digest(self):
        return stable_digest(self.configuration.model_dump(mode="json", exclude={"crm_sources"}))

    def guarded_bindings(self):
        registry = self.events.read(self.events.prefix + "-lifecycle-guards") or {}
        return set(registry.get("bindings", {})) | self.enrollments.keys()

    def _register(self, fence):
        if not self.enrollments:
            return

        def retain(doc):
            bindings = dict(doc.get("bindings", {}))
            for ref, row in self.enrollments.items():
                digest = stable_digest(row.to_dict())
                require(
                    ref not in bindings or bindings[ref] == digest, "CUSTOMER_ENROLLMENT_CHANGED"
                )
                bindings[ref] = digest
            digest = self.execution_digest()
            require(
                not doc.get("configuration_digest") or doc["configuration_digest"] == digest,
                "CUSTOMER_LIFECYCLE_CONFIGURATION_CHANGED",
            )
            doc.update(bindings=bindings, configuration_digest=digest)

        self.events.change(self.events.prefix + "-lifecycle-guards", retain, fence)

    def ref(self, row):
        return self.events.prefix + "-enrollment-" + stable_digest(row.enrollment_ref)

    def _current(self, row, *, now):
        stopped = trial_stop_reason(self, now)
        if stopped:
            return None, stopped
        binding = self.sales.progression.binding(row.binding_ref)
        account = self.events.account(binding.account_ref) or {}
        kinds = account.get("kinds", {})
        trigger_names = {
            "activation": ("signed_up",),
            "expansion": ("capacity_reached", "upgrade_requested"),
            "inbound": ("demo_requested", "inquiry_received"),
            "renewal": ("renewal_due",),
        }[row.goal]
        triggers = [
            kinds[k]
            for k in trigger_names
            if k in kinds and kinds[k]["event"]["source_ref"] in row.required_source_refs
        ]
        if not triggers:
            return None, "trigger_not_observed"
        trigger = max(triggers, key=lambda x: parsed(x["event"]["occurred_at"]))
        due = parsed(trigger["event"]["occurred_at"]) + timedelta(
            hours=row.activation_delay_hours if row.goal == "activation" else 0
        )
        if parsed(now) < due:
            return None, "activation_window_open"
        configured_sources = {
            s.source_ref: s for s in (*self.sales.sources, *self.configuration.crm_sources)
        }
        for source_ref in row.required_source_refs:
            configured = configured_sources[source_ref]
            self.events.validate_source_revision(configured)
            source = self.events.read(self.events.prefix + "-source-" + stable_digest(source_ref))
            if (
                not source
                or source["binding_digest"] != stable_digest(configured.to_dict())
                or parsed(source.get("covered_from", source["window_start"]))
                > parsed(trigger["event"]["occurred_at"])
                or parsed(source["through"]) < due
                or not 0
                <= (parsed(now) - parsed(source["through"])).total_seconds()
                <= row.max_source_age_seconds
            ):
                return None, "source_coverage_required"
        success_kind = {
            "activation": "activated",
            "expansion": "expanded",
            "inbound": None,
            "renewal": None,
        }[row.goal]
        if (
            success_kind
            and success_kind in kinds
            and parsed(kinds[success_kind]["event"]["occurred_at"])
            >= parsed(trigger["event"]["occurred_at"])
        ):
            return None, "outcome_already_observed"
        if row.goal == "renewal":
            cutoff = parsed(now) - timedelta(days=row.renewal_inactivity_days)
            last_used = kinds.get("product_used")
            if last_used and parsed(last_used["event"]["occurred_at"]) > cutoff:
                return None, "recent_product_activity"
            usage_sources = [
                s
                for s in self.sales.sources
                if s.source_ref in row.required_source_refs
                and any(m["kind"] == "product_used" for m in s.event_bindings.values())
            ]
            for source in usage_sources:
                covered = self.events.read(
                    self.events.prefix + "-source-" + stable_digest(source.source_ref)
                )
                if (
                    not covered
                    or parsed(covered.get("covered_from", covered["window_start"])) > cutoff
                ):
                    return None, "usage_coverage_required"
            state = self.sales.intake._scoped_state(
                self.sales.runner.runtimes["retention_chain"], row.retention_case_ref
            )
            require(
                state.ledger.account_ref == binding.account_ref, "CUSTOMER_RENEWAL_ACCOUNT_MISMATCH"
            )
            if state.status in {"renewed", "expanded", "churned", "lapsed"}:
                return None, "renewal_case_closed"
        if parsed(now) >= due + timedelta(days=row.trial_days):
            return None, "trial_expired"
        return trigger, None

    def admit(self, *, now, fence):
        self._register(fence)
        self.experiments.register(now=now, fence=fence)
        admitted, reports = set(), []
        from lightbulb.company_host_journal import HostAuthorityError
        from lightbulb.company_sales_host import _code

        for row in self.configuration.enrollments:
            try:
                eligible, details = self._admit_one(row, now=now, fence=fence)
                if eligible:
                    admitted.add(row.binding_ref)
                reports.extend(details)
            except (ValueError, LookupError) as error:
                if isinstance(error, HostAuthorityError):
                    raise
                reports.append(
                    {
                        "enrollment_ref": row.enrollment_ref,
                        "status": "blocked",
                        "code": _code(error),
                    }
                )
        return admitted, reports

    def _admit_one(self, row, *, now, fence):
        from lightbulb.company_sales_intake import SalesIntakeCandidate

        reports = []
        ref = self.ref(row)
        old = self.events.read(ref)
        require(
            not old or old["configuration_digest"] == stable_digest(row.to_dict()),
            "CUSTOMER_ENROLLMENT_CHANGED",
        )
        trigger, reason = self._current(row, now=now)
        if reason:
            reports.append(
                {"enrollment_ref": row.enrollment_ref, "status": "held", "reason": reason}
            )
            return False, reports
        if old and old.get("stopped"):
            reports.append({"enrollment_ref": row.enrollment_ref, "status": "stopped"})
            return False, reports
        binding = self.sales.progression.binding(row.binding_ref)
        self.experiments.guard(binding, now=now, fence=fence)
        if old is None:
            observed = trigger["event"]["occurred_at"]
            expires = (
                (
                    parsed(observed)
                    + timedelta(
                        hours=row.activation_delay_hours if row.goal == "activation" else 0,
                        days=row.trial_days,
                    )
                )
                .isoformat()
                .replace("+00:00", "Z")
            )
            candidate = SalesIntakeCandidate(
                candidate_ref="customer-" + stable_digest(ref),
                kind="verified_event",
                binding=binding,
                facts=row.facts,
                facts_evidence_refs=row.facts_evidence_refs,
                observed_at=observed,
                expires_at=expires,
                customer_event_ref=trigger["event_journal_ref"],
                customer_event_digest=stable_digest(trigger["event"]),
            )

            def retain(doc):
                require(
                    not doc.get("candidate") or doc["candidate"] == candidate.to_dict(),
                    "CUSTOMER_ENROLLMENT_RACE",
                )
                doc.update(
                    configuration_digest=stable_digest(row.to_dict()),
                    candidate=candidate.to_dict(),
                    enrollment_ref=row.enrollment_ref,
                    goal=row.goal,
                    source_event_ref=trigger["event_journal_ref"],
                    source_event_digest=stable_digest(trigger["event"]),
                    stopped=False,
                )

            old = self.events.change(ref, retain, fence)
        # A new trigger cannot replace the original admitted prospect/source.
        require(
            old["source_event_ref"] == trigger["event_journal_ref"],
            "CUSTOMER_ENROLLMENT_TRIGGER_CHANGED",
        )
        if row.goal == "renewal":
            from lightbulb.customer_renewal_outcomes import record_renewal_risk

            record_renewal_risk(self, row, trigger, now=now, fence=fence)
        self.sales.intake.ingest(old["candidate"], now=now, fence=fence)
        reports.append(
            {"enrollment_ref": row.enrollment_ref, "status": "admitted", "approval_required": True}
        )
        return True, reports

    def guard(self, binding, *, now, fence):
        self.experiments.guard(binding, now=now, fence=fence)
        row = self.enrollments.get(binding.binding_ref)
        if row is None:
            require(
                binding.binding_ref not in self.guarded_bindings(),
                "CUSTOMER_ENROLLMENT_CONFIGURATION_REQUIRED",
            )
            return
        registry = self.events.read(self.events.prefix + "-lifecycle-guards") or {}
        require(
            registry.get("configuration_digest") == self.execution_digest(),
            "CUSTOMER_LIFECYCLE_CONFIGURATION_CHANGED",
        )
        doc = self.events.read(self.ref(row))
        require(doc is not None and not doc.get("stopped"), "CUSTOMER_ENROLLMENT_HELD")
        trigger, reason = self._current(row, now=now)
        require(
            reason is None and trigger["event_journal_ref"] == doc["source_event_ref"],
            "CUSTOMER_ENROLLMENT_" + (reason or "source_changed").upper(),
        )
        state = self.sales._state(binding)
        require(state.ledger.touches < row.max_touches, "CUSTOMER_ENROLLMENT_TOUCH_LIMIT")
        fence()

    def reserve_touch(self, binding, state, *, fence):
        trial = self.configuration.trial
        if trial is None or binding.binding_ref not in self.enrollments:
            return
        ref = self.events.prefix + "-trial-slots-" + stable_digest(trial.trial_ref)
        slot = stable_digest({"binding": binding.binding_ref, "step": state.ledger.next_step})

        def reserve(doc):
            require(
                not doc.get("trial_digest")
                or doc["trial_digest"] == stable_digest(trial.to_dict()),
                "CUSTOMER_TRIAL_CHANGED",
            )
            slots = dict(doc.get("slots", {}))
            require(
                slot in slots or len(slots) < trial.max_total_touches, "CUSTOMER_TRIAL_TOUCH_LIMIT"
            )
            slots[slot] = {"binding_ref": binding.binding_ref, "step": state.ledger.next_step}
            doc.update(trial_digest=stable_digest(trial.to_dict()), slots=slots)

        self.events.change(ref, reserve, fence)

    def observe(self, *, now, fence):
        self.experiments.observe(now=now, fence=fence)
        from lightbulb.company_sales_host import TOUCH_SCHEMA

        reports = []
        for row in self.configuration.enrollments:
            ref = self.ref(row)
            doc = self.events.read(ref)
            if not doc:
                continue
            binding = self.sales.progression.binding(row.binding_ref)
            first = self.sales._read(self.sales._ref(binding) + "-1", TOUCH_SCHEMA)
            if not first or first.get("phase") != "applied":
                continue
            effect = first["effect"]
            completed = effect["completed_at"]
            account = self.events.account(binding.account_ref) or {}
            kinds = account.get("kinds", {})
            kind = {
                "activation": "activated",
                "expansion": "expanded",
                "inbound": None,
                "renewal": None,
            }[row.goal]
            observation = kinds.get(kind) if kind else None
            if (
                observation
                and observation["event"]["source_ref"] in row.required_source_refs
                and parsed(completed) <= parsed(observation["event"]["occurred_at"]) <= parsed(now)
            ):
                result = {
                    "kind": kind,
                    "observed_at": observation["event"]["occurred_at"],
                    "event_ref": observation["event_journal_ref"],
                    "evidence_digest": stable_digest(observation["event"]),
                    "effect_digest": stable_digest(effect),
                    "basis": "observed_after_intervention",
                    "causal_uplift_verified": False,
                }

                def retain(current):
                    if not current.get("outcome"):
                        current.update(outcome=result, stopped=True)

                self.events.change(ref, retain, fence)
                reports.append(result)
            if row.goal == "renewal":
                from lightbulb.customer_renewal_outcomes import verified_renewal_outcome

                result = verified_renewal_outcome(self, row, first, now=now)
                if result:

                    def retain_renewal(current):
                        if not current.get("outcome"):
                            current.update(outcome=result, stopped=True)

                    self.events.change(ref, retain_renewal, fence)
                    reports.append(result)
            if row.goal == "inbound":
                meeting = self.sales.progression.meetings.status(binding.binding_ref)
                if meeting and meeting["action"] == "meeting_recorded":
                    proposal = self.sales.progression.read(meeting["proposal_ref"])
                    verified = proposal["verified"]
                    if (
                        parsed(completed)
                        <= parsed(verified["receipt"]["completed_at"])
                        <= parsed(now)
                    ):
                        result = {
                            "kind": "meeting_booked",
                            "observed_at": verified["receipt"]["completed_at"],
                            "event_ref": meeting["proposal_ref"],
                            "evidence_digest": stable_digest(verified),
                            "effect_digest": stable_digest(effect),
                            "basis": "observed_after_intervention",
                            "causal_uplift_verified": False,
                        }

                        def retain_meeting(current):
                            if not current.get("outcome"):
                                current.update(outcome=result, stopped=True)

                        self.events.change(ref, retain_meeting, fence)
                        reports.append(result)
        return reports

    def report(self):
        return [
            {
                "enrollment_ref": r.enrollment_ref,
                "goal": r.goal,
                "state": self.events.read(self.ref(r)),
            }
            for r in self.configuration.enrollments
        ]
