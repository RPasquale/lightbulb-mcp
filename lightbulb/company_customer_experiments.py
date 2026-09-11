"""Fixed customer cohorts over the canonical sealed experiment mechanics.

Assignments are intention-to-treat denominators. Applied communication receipts
are exposure diagnostics, never a prerequisite for observing control outcomes.
"""

from pydantic import Field
from lightbulb.company_engine_core import StrictModel, OpaqueRef, parsed, stable_digest
from lightbulb.company_customer_events import require
from lightbulb.growth_experiments import (
    GrowthExperimentDesign,
    assign_experiment_unit,
    verify_growth_experiment_design,
    verify_experiment_assignment,
    mint_experiment_arm_evidence,
    read_out_growth_experiment,
)


class CustomerLifecycleExperiment(StrictModel):
    design: GrowthExperimentDesign
    binding_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=100)


class CompanyCustomerExperiments:
    def __init__(self, lifecycle, configuration=()):
        self.lifecycle, self.events = lifecycle, lifecycle.events
        self.configuration = tuple(
            CustomerLifecycleExperiment.model_validate(c) for c in configuration
        )
        require(len(self.configuration) <= 20, "CUSTOMER_EXPERIMENT_CAPACITY")
        self.authority = dict(
            scope=self.events.gateway.authority_scope,
            scope_keyring=self.events.gateway.keyring,
        )
        self.prefix = self.events.prefix + "-experiments"
        self.rows = {r.binding_ref: r for r in lifecycle.configuration.enrollments}
        refs, bindings, accounts = set(), set(), set()
        for c in self.configuration:
            d = verify_growth_experiment_design(c.design, **self.authority)
            require(
                d.assignment_unit == "customer", "CUSTOMER_EXPERIMENT_UNIT_REQUIRED"
            )
            require(d.design_ref not in refs, "CUSTOMER_EXPERIMENT_DUPLICATED")
            refs.add(d.design_ref)
            require(
                len(set(c.binding_refs)) == len(c.binding_refs)
                and not bindings.intersection(c.binding_refs),
                "CUSTOMER_EXPERIMENT_BINDING_DUPLICATED",
            )
            bindings.update(c.binding_refs)
            require(
                set(c.binding_refs) <= self.rows.keys(),
                "CUSTOMER_EXPERIMENT_ENROLLMENT_REQUIRED",
            )
            goal = {
                "customer_activation": "activation",
                "customer_expansion": "expansion",
            }.get(d.hypothesis.metric_name)
            require(
                goal is not None
                and all(self.rows[b].goal == goal for b in c.binding_refs),
                "CUSTOMER_EXPERIMENT_METRIC_UNSUPPORTED",
            )
            selected_accounts = {
                lifecycle.sales.progression.binding(b).account_ref
                for b in c.binding_refs
            }
            require(
                not accounts.intersection(selected_accounts),
                "CUSTOMER_EXPERIMENT_ACCOUNT_OVERLAP",
            )
            accounts.update(selected_accounts)
            require(
                all(
                    r.binding_ref in c.binding_refs
                    for r in self.rows.values()
                    if lifecycle.sales.progression.binding(r.binding_ref).account_ref
                    in selected_accounts
                ),
                "CUSTOMER_EXPERIMENT_ACCOUNT_COHORT_INCOMPLETE",
            )
        self.by_binding = {b: c for c in self.configuration for b in c.binding_refs}

    def _ref(self, c):
        return self.prefix + "-" + stable_digest(c.design.design_ref)

    def _definition(self, c):
        sources = {
            s.source_ref: s
            for s in (
                *self.lifecycle.sales.sources,
                *self.lifecycle.configuration.crm_sources,
            )
        }
        return {
            "configuration": c.to_dict(),
            "enrollments": [self.rows[b].to_dict() for b in c.binding_refs],
            "sources": {
                ref: sources[ref].to_dict()
                for b in c.binding_refs
                for ref in self.rows[b].required_source_refs
            },
        }

    def register(self, *, now, fence):
        """Freeze all units before exposure; registering after the start fails closed."""
        from lightbulb.company_sales_host import TOUCH_SCHEMA

        for c in self.configuration:
            definition = self._definition(c)
            digest = stable_digest(definition)

            def register(doc):
                if doc.get("definition_digest"):
                    require(
                        doc["definition_digest"] == digest,
                        "CUSTOMER_EXPERIMENT_CHANGED",
                    )
                    return
                require(
                    parsed(now) <= parsed(c.design.exposure_start),
                    "CUSTOMER_EXPERIMENT_LATE_REGISTRATION",
                )
                units = {}
                for ref in c.binding_refs:
                    b = self.lifecycle.sales.progression.binding(ref)
                    require(
                        not self.lifecycle.sales._read(
                            self.lifecycle.sales._ref(b) + "-1", TOUCH_SCHEMA
                        ),
                        "CUSTOMER_EXPERIMENT_PRIOR_INTERVENTION",
                    )
                    a = assign_experiment_unit(
                        c.design, b.account_ref, **self.authority
                    )
                    units.setdefault(
                        a.unit_digest,
                        {"assignment": a.model_dump(mode="json"), "bindings": []},
                    )["bindings"].append(ref)
                doc.update(
                    definition_digest=digest,
                    definition=definition,
                    registered_at=now,
                    units=units,
                )

            def guard_registry(doc):
                guards = doc.setdefault("bindings", {})
                accounts = doc.setdefault("accounts", {})
                for b in c.binding_refs:
                    require(
                        b not in guards or guards[b] == c.design.design_ref,
                        "CUSTOMER_EXPERIMENT_REASSIGNMENT",
                    )
                    guards[b] = c.design.design_ref
                    account = self.lifecycle.sales.progression.binding(b).account_ref
                    require(
                        account not in accounts
                        or accounts[account] == c.design.design_ref,
                        "CUSTOMER_EXPERIMENT_ACCOUNT_OVERLAP",
                    )
                    accounts[account] = c.design.design_ref
                require(len(guards) <= 100, "CUSTOMER_EXPERIMENT_CAPACITY")

            self.events.change(self.prefix, guard_registry, fence)
            self.events.change(self._ref(c), register, fence)

    def guard(self, binding, *, now, fence):
        c = self.by_binding.get(binding.binding_ref)
        registry = self.events.read(self.prefix) or {}
        retained = registry.get("bindings", {})
        require(
            c is not None
            or (
                binding.binding_ref not in retained
                and binding.account_ref not in registry.get("accounts", {})
            ),
            "CUSTOMER_EXPERIMENT_CONFIGURATION_REQUIRED",
        )
        if c is None:
            return
        self.register(now=now, fence=fence)
        d = c.design
        require(
            parsed(now) >= parsed(d.exposure_start), "CUSTOMER_EXPERIMENT_NOT_STARTED"
        )
        require(parsed(now) < parsed(d.readout_horizon), "CUSTOMER_EXPERIMENT_ENDED")
        a = assign_experiment_unit(d, binding.account_ref, **self.authority)
        control = next(v.variant_ref for v in d.variants if v.is_control)
        require(a.variant_ref != control, "CUSTOMER_EXPERIMENT_HOLDOUT")

    def _observations(self, c, unit, *, now):
        from lightbulb.company_sales_host import TOUCH_SCHEMA

        d, successes, exposures, complete = c.design, [], [], True
        kind = {"customer_activation": "activated", "customer_expansion": "expanded"}[
            d.hypothesis.metric_name
        ]
        sources = {s.source_ref: s for s in self.lifecycle.sales.sources}
        for ref in unit["bindings"]:
            row, binding = self.rows[ref], self.lifecycle.sales.progression.binding(ref)
            touch = self.lifecycle.sales._read(
                self.lifecycle.sales._ref(binding) + "-1", TOUCH_SCHEMA
            )
            if touch and touch.get("phase") == "applied":
                effect = touch["effect"]
                if (
                    parsed(d.exposure_start)
                    <= parsed(effect["completed_at"])
                    < parsed(d.readout_horizon)
                ):
                    exposures.append(stable_digest(effect))
            for source_ref in row.required_source_refs:
                source = sources[source_ref]
                self.events.validate_source_revision(source)
                coverage = self.events.read(
                    self.events.prefix + "-source-" + stable_digest(source_ref)
                )
                complete = complete and bool(
                    coverage
                    and coverage["binding_digest"] == stable_digest(source.to_dict())
                    and not coverage.get("unmapped_identities")
                    and parsed(coverage["covered_from"]) <= parsed(d.exposure_start)
                    and parsed(coverage["through"]) >= parsed(d.readout_horizon)
                    and parsed(coverage["through"]) <= parsed(now)
                )
            observed = (
                (self.events.account(binding.account_ref) or {}).get("kinds") or {}
            ).get(kind)
            if observed:
                event = observed["event"]
                retained = self.events.read(observed["event_journal_ref"])
                require(
                    retained
                    and retained["event"] == event
                    and retained.get("proof", {}).get("receipt")
                    and event["account_ref"] == binding.account_ref,
                    "CUSTOMER_EXPERIMENT_EVENT_INVALID",
                )
                if event["source_ref"] not in row.required_source_refs:
                    complete = False
                elif (
                    parsed(d.exposure_start)
                    <= parsed(event["occurred_at"])
                    < parsed(d.readout_horizon)
                ):
                    if parsed(event["occurred_at"]) <= parsed(now):
                        successes.append(observed["event_journal_ref"])
                elif parsed(event["occurred_at"]) >= parsed(d.readout_horizon):
                    # The latest-kind index cannot prove absence of an earlier event.
                    complete = False
        return sorted(set(successes)), sorted(set(exposures)), complete

    def observe(self, *, now, fence):
        for c in self.configuration:
            old = self.events.read(self._ref(c))
            if not old:
                continue
            require(
                old["definition_digest"] == stable_digest(self._definition(c)),
                "CUSTOMER_EXPERIMENT_CHANGED",
            )
            observations = {
                key: self._observations(c, unit, now=now)
                for key, unit in old["units"].items()
            }

            def retain(doc):
                for key, (successes, exposures, complete) in observations.items():
                    unit = doc["units"][key]
                    unit["outcomes"] = sorted(
                        set(unit.get("outcomes", ())) | set(successes)
                    )
                    unit["exposures"] = sorted(
                        set(unit.get("exposures", ())) | set(exposures)
                    )
                    unit["complete"] = complete
                doc["observed_at"] = now

            self.events.change(self._ref(c), retain, fence)

    def readout(self, design_ref, *, now, fence):
        c = next(
            (c for c in self.configuration if c.design.design_ref == design_ref), None
        )
        require(c is not None, "CUSTOMER_EXPERIMENT_CONFIGURATION_REQUIRED")
        if parsed(now) < parsed(c.design.readout_horizon):
            return {"status": "immature", "causal_uplift_verified": False}
        old = self.events.read(self._ref(c)) or {}
        require(
            not old or old["definition_digest"] == stable_digest(self._definition(c)),
            "CUSTOMER_EXPERIMENT_CHANGED",
        )
        if old.get("readout"):
            return old["readout"]
        self.observe(now=now, fence=fence)
        doc = self.events.read(self._ref(c))
        if not doc or any(
            not u.get("complete") and not u.get("outcomes")
            for u in doc["units"].values()
        ):
            return {
                "status": "source_coverage_required",
                "causal_uplift_verified": False,
            }
        arms = []
        for variant in c.design.variants:
            units = []
            for unit in doc["units"].values():
                a = verify_experiment_assignment(unit["assignment"], **self.authority)
                require(
                    a.design_digest == c.design.design_digest,
                    "CUSTOMER_EXPERIMENT_ASSIGNMENT_MISMATCH",
                )
                if a.variant_ref == variant.variant_ref:
                    units.append(unit)
            if variant.is_control and any(u.get("exposures") for u in units):
                return {
                    "status": "control_contaminated",
                    "causal_uplift_verified": False,
                }
            arms.append(
                mint_experiment_arm_evidence(
                    {
                        "observation_ref": "lifecycle-" + variant.variant_ref[:50],
                        "design_digest": c.design.design_digest,
                        "variant_ref": variant.variant_ref,
                        "metric_kind": "proportion",
                        "connector_account_ref": "host.lifecycle",
                        "provider": "lightbulb_lifecycle",
                        "source_capability": "lightbulb.lifecycle_cohort_outcomes",
                        "observed_at": now,
                        "window_start": c.design.exposure_start,
                        "window_end": c.design.readout_horizon,
                        "successes": sum(bool(u.get("outcomes")) for u in units),
                        "trials": len(units),
                        "evidence_digest": stable_digest(units),
                    },
                    **self.authority,
                )
            )
        result = read_out_growth_experiment(
            c.design,
            arms,
            readout_ref="lifecycle-readout",
            analysis_as_of=now,
            **self.authority,
        )
        report = {
            "status": result.verdict,
            "readout": result.model_dump(mode="json"),
            "causal_uplift_verified": result.causal and result.verdict == "win",
            "basis": "randomized_assignment_intention_to_treat",
            "execution_authorized": False,
        }

        def finish(current):
            current.setdefault("readout", report)

        return self.events.change(self._ref(c), finish, fence)["readout"]

    def report(self):
        return [
            {
                "design_ref": c.design.design_ref,
                "state": self.events.read(self._ref(c)),
                "execution_authorized": False,
            }
            for c in self.configuration
        ]
