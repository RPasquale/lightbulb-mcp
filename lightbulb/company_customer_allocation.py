"""Customer outcome evidence feeding the existing growth portfolio allocator.

Activation uplift is not monetary uplift. This bridge proposes bounded trials
from unallocated capacity, preserving current campaigns and control assignments.
It grants neither budget authority nor permission to dispatch customer actions.
"""

from decimal import Decimal, ROUND_DOWN
from typing import Literal
from pydantic import Field, field_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    decimal_value,
    parsed,
    stable_digest,
    timestamp,
)
from lightbulb.company_customer_events import require
from lightbulb.growth_engine_loop import (
    Channel,
    GrowthEngineLoopPlan,
    CampaignPortfolio,
    plan_campaign_portfolio,
)


class CustomerFinancialEvidenceRef(StrictModel):
    kind: Literal["one_time", "subscription"]
    report_ref: OpaqueRef


class CustomerOutcomeCandidate(StrictModel):
    candidate_ref: OpaqueRef
    experiment_ref: OpaqueRef
    channel: Channel
    audience_ref: OpaqueRef
    worker_role_ref: OpaqueRef
    financial_reports: tuple[CustomerFinancialEvidenceRef, ...] = Field(min_length=1, max_length=10)
    trial_budget: Decimal = Field(gt=0)
    trial_worker_minutes: int = Field(ge=1, le=10000, strict=True)
    # Explicit review reserve for costs not represented by canonical recorded costs.
    unrecorded_cost_reserve: Decimal = Field(ge=0)
    cost_review_ref: OpaqueRef

    @field_validator("trial_budget", "unrecorded_cost_reserve", mode="before")
    @classmethod
    def money(cls, value, info):
        return decimal_value(value, field_name=info.field_name)


class CustomerOutcomeAllocationRequest(StrictModel):
    allocation_ref: OpaqueRef
    expected_plan_digest: Sha256Digest
    expected_portfolio_digest: Sha256Digest
    candidates: tuple[CustomerOutcomeCandidate, ...] = Field(min_length=1, max_length=20)
    budget_limit: Decimal = Field(gt=0)
    worker_minutes_limit: int = Field(ge=1, le=100000, strict=True)
    trial_ends_at: str
    max_evidence_age_hours: int = Field(default=24, ge=1, le=168, strict=True)
    minimum_sample_per_arm: int = Field(default=30, ge=2, le=1000000, strict=True)
    maximum_contribution_drop_percent: int = Field(default=20, ge=0, le=100, strict=True)

    @field_validator("budget_limit", mode="before")
    @classmethod
    def money(cls, value):
        return decimal_value(value, field_name="budget_limit")

    @field_validator("trial_ends_at")
    @classmethod
    def end(cls, value):
        return timestamp(value, field_name="trial_ends_at")


class CompanyCustomerAllocation:
    def __init__(self, progression):
        self.p, self.host = progression, progression.host
        self.events = progression.commerce.events
        self.prefix = self.events.prefix + "-customer-allocation-"

    def _experiments(self, experiments):
        from lightbulb.company_customer_experiments import CompanyCustomerExperiments

        require(
            isinstance(experiments, CompanyCustomerExperiments)
            and experiments.lifecycle.sales is self.host,
            "CUSTOMER_ALLOCATION_EXPERIMENT_HOST_MISMATCH",
        )

    def _evidence(self, candidate, request, experiments, *, now, fence):
        from lightbulb.growth_experiments import (
            verify_growth_experiment_design,
            verify_growth_experiment_readout,
        )

        configuration = next(
            (
                c
                for c in experiments.configuration
                if c.design.design_ref == candidate.experiment_ref
            ),
            None,
        )
        require(configuration is not None, "CUSTOMER_ALLOCATION_EXPERIMENT_REQUIRED")
        design = verify_growth_experiment_design(configuration.design, **experiments.authority)
        require(
            design.hypothesis.direction == "increase"
            and design.hypothesis.metric_name in {"customer_activation", "customer_expansion"},
            "CUSTOMER_ALLOCATION_OUTCOME_METRIC_REQUIRED",
        )
        measured = experiments.readout(candidate.experiment_ref, now=now, fence=fence)
        result = dict(
            candidate_ref=candidate.candidate_ref,
            status="experiment_evidence_required",
            experiment_digest=design.design_digest,
            financial_evidence=[],
            causal_profit_verified=False,
            execution_authorized=False,
        )
        if "readout" not in measured:
            return result
        readout = verify_growth_experiment_readout(measured["readout"], **experiments.authority)
        require(
            readout.design_digest == design.design_digest, "CUSTOMER_ALLOCATION_DESIGN_MISMATCH"
        )
        result["readout_digest"] = stable_digest(readout.to_dict())
        if (
            not 0
            <= (parsed(now) - parsed(readout.analysis_as_of)).total_seconds()
            <= request.max_evidence_age_hours * 3600
        ):
            return {**result, "status": "stale_experiment"}
        if (
            not readout.causal
            or readout.underpowered
            or not readout.sample_ratio_check.passed
            or readout.guardrail_breaches
            or readout.verdict != "win"
            or readout.ci_low is None
            or readout.ci_low <= 0
            or len(readout.arms) != 2
            or any(
                a.trials is None or a.trials < request.minimum_sample_per_arm for a in readout.arms
            )
        ):
            return result
        cohort = set(configuration.binding_refs)
        seen, rows, fingerprints = set(), [], []
        for reference in candidate.financial_reports:
            suffix = (
                "financial-report-"
                if reference.kind == "one_time"
                else "subscription-financial-report-"
            )
            document = self.events.read(
                self.events.prefix + "-" + suffix + stable_digest(reference.report_ref)
            )
            require(
                document and document.get("report"), "CUSTOMER_ALLOCATION_FINANCIAL_REPORT_REQUIRED"
            )
            report = document["report"]
            require(
                report.get("report_ref") == reference.report_ref,
                "CUSTOMER_ALLOCATION_FINANCIAL_REPORT_MISMATCH",
            )
            age = (parsed(now) - parsed(report["observed_at"])).total_seconds()
            if not 0 <= age <= request.max_evidence_age_hours * 3600:
                return {**result, "status": "stale_financials"}
            if report.get("unallocated_cost_sources"):
                return {**result, "status": "cost_allocation_required"}
            for row in report["orders" if reference.kind == "one_time" else "subscriptions"]:
                require(
                    row["binding_ref"] in cohort
                    and self.p.binding(row["binding_ref"]).account_ref == row["account_ref"],
                    "CUSTOMER_ALLOCATION_CUSTOMER_OUTSIDE_COHORT",
                )
                key = (reference.kind, row["offer_ref"])
                require(key not in seen, "CUSTOMER_ALLOCATION_DUPLICATE_FINANCIALS")
                seen.add(key)
                if row.get("contribution_after_recorded_costs") is None:
                    return {**result, "status": "financial_coverage_required"}
                rows.append(row)
            fingerprints.append(
                dict(
                    kind=reference.kind,
                    report_ref=reference.report_ref,
                    report_digest=stable_digest(report),
                )
            )
        require(rows, "CUSTOMER_ALLOCATION_FINANCIAL_REPORT_EMPTY")
        currencies = {r["currency"] for r in rows}
        require(len(currencies) == 1, "CUSTOMER_ALLOCATION_CURRENCY_MISMATCH")
        contribution = sum(
            (Decimal(r["contribution_after_recorded_costs"]) for r in rows), Decimal(0)
        )
        reserve_adjusted = contribution - candidate.unrecorded_cost_reserve
        return {
            **result,
            "status": "trial_eligible" if reserve_adjusted > 0 else "nonpositive_contribution",
            "currency": currencies.pop(),
            "financial_evidence": fingerprints,
            "financial_keys": [list(k) for k in sorted(seen)],
            "observed_contribution_after_recorded_costs": str(contribution),
            "reviewed_unrecorded_cost_reserve": str(candidate.unrecorded_cost_reserve),
            "reserve_adjusted_contribution": str(reserve_adjusted),
            "recorded_cost_total": str(
                sum((Decimal(r["recorded_cost_total"]) for r in rows), Decimal(0))
            ),
            "cost_coverage_complete": all(r.get("cost_coverage_complete", False) for r in rows),
            "financial_customer_count": len({r["account_ref"] for r in rows}),
            "financial_window_basis": "retained_order_or_subscription_coverage_not_experiment_window",
            "causal_outcome_verified": True,
        }

    def propose(self, request, *, plan, portfolio, experiments, now, fence):
        request = CustomerOutcomeAllocationRequest.model_validate(request)
        self._experiments(experiments)
        now = self.host._now(now)
        retained_index = self.events.read(self.prefix + "index") or {}
        retained_refs = retained_index.get("refs", [])
        require(
            request.allocation_ref in retained_refs or len(retained_refs) < 100,
            "CUSTOMER_ALLOCATION_CAPACITY",
        )
        plan = GrowthEngineLoopPlan.model_validate(plan)
        portfolio = CampaignPortfolio.model_validate(portfolio)
        workforce = self.host.runner.bundle.workforce_plan
        require(
            workforce is not None
            and workforce.currency == portfolio.currency
            and all(workforce.worker(c.worker_role_ref) is not None for c in request.candidates),
            "CUSTOMER_ALLOCATION_WORKFORCE_CONFIGURATION_REQUIRED",
        )
        require(
            plan.plan_digest == request.expected_plan_digest == portfolio.plan_digest
            and portfolio.portfolio_digest == request.expected_portfolio_digest,
            "CUSTOMER_ALLOCATION_PLAN_CHANGED",
        )
        definition = dict(
            request=request.to_dict(), plan=plan.to_dict(), portfolio=portfolio.to_dict()
        )
        retained = self.events.read(self.prefix + stable_digest(request.allocation_ref))
        if retained and retained.get("proposal"):
            require(retained.get("definition") == definition, "CUSTOMER_ALLOCATION_CHANGED")
            require(
                retained["proposal"]["source_workforce_plan_digest"] == workforce.plan_digest,
                "CUSTOMER_ALLOCATION_WORKFORCE_CHANGED",
            )
            self._register(request.allocation_ref, fence)
            return retained["proposal"]
        require(
            parsed(portfolio.period_start)
            <= parsed(now)
            < parsed(request.trial_ends_at)
            <= parsed(portfolio.period_end)
            and (parsed(request.trial_ends_at) - parsed(now)).total_seconds() <= 30 * 86400,
            "CUSTOMER_ALLOCATION_TRIAL_WINDOW_INVALID",
        )
        refs = [c.candidate_ref for c in request.candidates]
        require(len(set(refs)) == len(refs), "CUSTOMER_ALLOCATION_DUPLICATE_CANDIDATE")
        require(
            len({c.experiment_ref for c in request.candidates}) == len(refs),
            "CUSTOMER_ALLOCATION_DUPLICATE_EXPERIMENT",
        )
        evidence = [
            self._evidence(c, request, experiments, now=now, fence=fence)
            for c in request.candidates
        ]
        seen = set()
        for row in evidence:
            keys = {tuple(k) for k in row.get("financial_keys", [])}
            require(not seen.intersection(keys), "CUSTOMER_ALLOCATION_DUPLICATE_FINANCIALS")
            seen.update(keys)
            require(
                not row.get("currency") or row["currency"] == portfolio.currency,
                "CUSTOMER_ALLOCATION_CURRENCY_MISMATCH",
            )
        by_ref = {c.candidate_ref: c for c in request.candidates}
        # Prioritize observed contribution conservatively; it is not incremental ROAS.
        eligible = sorted(
            (r for r in evidence if r["status"] == "trial_eligible"),
            key=lambda r: (-Decimal(r["reserve_adjusted_contribution"]), r["candidate_ref"]),
        )
        budget = min(request.budget_limit, portfolio.unallocated)
        minutes = request.worker_minutes_limit
        allocations = [
            dict(
                envelope_ref=e.envelope_ref,
                channel=e.channel,
                objective=e.objective,
                audience_ref=e.audience_ref,
                budget=str(e.budget),
            )
            for e in portfolio.envelopes
        ]
        trials = []
        proposed = portfolio
        for row in eligible:
            candidate = by_ref[row["candidate_ref"]]
            amount = min(budget, candidate.trial_budget).quantize(
                Decimal("0.01"), rounding=ROUND_DOWN
            )
            if (
                amount < candidate.trial_budget
                or minutes < candidate.trial_worker_minutes
                or len(allocations) >= 64
            ):
                row["status"] = "capacity_required"
                continue
            envelope_ref = (
                "customer-trial-"
                + stable_digest([request.allocation_ref, candidate.candidate_ref])[:32]
            )
            extra = dict(
                envelope_ref=envelope_ref,
                channel=candidate.channel,
                objective="retain",
                audience_ref=candidate.audience_ref,
                budget=str(amount),
            )
            try:
                next_portfolio = plan_campaign_portfolio(
                    plan,
                    period_start=portfolio.period_start,
                    period_end=portfolio.period_end,
                    total_budget=portfolio.total_budget,
                    allocations=[*allocations, extra],
                )
            except ValueError:
                row["status"] = "channel_capacity_or_configuration_required"
                continue
            allocations.append(extra)
            proposed = next_portfolio
            budget -= amount
            minutes -= candidate.trial_worker_minutes
            trials.append(
                dict(
                    candidate_ref=candidate.candidate_ref,
                    envelope_ref=envelope_ref,
                    budget=str(amount),
                    worker_role_ref=candidate.worker_role_ref,
                    proposed_worker_minutes=candidate.trial_worker_minutes,
                    ends_at=request.trial_ends_at,
                    stop_on=[
                        "deadline",
                        "stale_evidence",
                        "nonpositive_contribution",
                        "contribution_drop",
                        "changed_experiment",
                        "recorded_cost_budget_exhausted",
                        "new_holdout",
                    ],
                    requires_human_approval=True,
                    execution_authorized=False,
                )
            )
        report = dict(
            schema="lightbulb.customer_outcome_allocation.v1",
            allocation_ref=request.allocation_ref,
            observed_at=now,
            evidence=evidence,
            trials=trials,
            proposed_portfolio=proposed.to_dict(),
            source_portfolio_digest=portfolio.portfolio_digest,
            source_plan_digest=plan.plan_digest,
            source_workforce_plan_digest=workforce.plan_digest,
            ranking_basis="observed_contribution_less_reviewed_reserve_not_incremental_return",
            requires_human_approval=True,
            execution_authorized=False,
            causal_profit_verified=False,
            workforce_assignment_performed=False,
            active_campaigns_modified=False,
        )
        report["proposal_digest"] = stable_digest(report)

        def retain(doc):
            require(doc.get("definition", definition) == definition, "CUSTOMER_ALLOCATION_CHANGED")
            require(
                not doc.get("proposal")
                or doc["proposal"]["proposal_digest"] == report["proposal_digest"],
                "CUSTOMER_ALLOCATION_REVIEW_STALE",
            )
            doc.update(definition=definition, proposal=report)

        self.events.change(self.prefix + stable_digest(request.allocation_ref), retain, fence)

        self._register(request.allocation_ref, fence)
        return report

    def _register(self, allocation_ref, fence):
        def index(doc):
            refs = doc.setdefault("refs", [])
            if allocation_ref not in refs:
                require(len(refs) < 100, "CUSTOMER_ALLOCATION_CAPACITY")
                refs.append(allocation_ref)

        self.events.change(self.prefix + "index", index, fence)

    def observe(self, allocation_ref, *, experiments, now, fence):
        """Recheck retained proposals; stop recommendations never authorize execution."""
        self._experiments(experiments)
        ref = self.prefix + stable_digest(allocation_ref)
        doc = self.events.read(ref)
        require(doc and doc.get("proposal"), "CUSTOMER_ALLOCATION_REQUIRED")
        request = CustomerOutcomeAllocationRequest.model_validate(doc["definition"]["request"])
        workforce = self.host.runner.bundle.workforce_plan
        require(
            workforce is not None
            and workforce.plan_digest == doc["proposal"]["source_workforce_plan_digest"],
            "CUSTOMER_ALLOCATION_WORKFORCE_CHANGED",
        )
        original = {r["candidate_ref"]: r for r in doc["proposal"]["evidence"]}
        trials = {t["candidate_ref"]: t for t in doc["proposal"]["trials"]}
        rows = []
        for candidate in request.candidates:
            if candidate.candidate_ref not in trials:
                continue
            trial = trials[candidate.candidate_ref]
            prior = original[candidate.candidate_ref]
            if parsed(now) >= parsed(request.trial_ends_at):
                rows.append(
                    dict(
                        candidate_ref=candidate.candidate_ref,
                        status="stop",
                        reason="deadline",
                        budget=trial["budget"],
                        execution_authorized=False,
                        spend_guard="existing_growth_envelope_authority_required",
                    )
                )
                continue
            current = self._evidence(candidate, request, experiments, now=now, fence=fence)
            reason = None
            if current["status"] != "trial_eligible":
                reason = current["status"]
            elif current["experiment_digest"] != prior["experiment_digest"] or current.get(
                "readout_digest"
            ) != prior.get("readout_digest"):
                reason = "changed_experiment"
            else:
                before = Decimal(prior["reserve_adjusted_contribution"])
                after = Decimal(current["reserve_adjusted_contribution"])
                if after < before * (100 - request.maximum_contribution_drop_percent) / 100:
                    reason = "contribution_drop"
                if Decimal(current["recorded_cost_total"]) - Decimal(
                    prior["recorded_cost_total"]
                ) >= Decimal(trial["budget"]):
                    reason = "recorded_cost_budget_exhausted"
                source = next(
                    c
                    for c in experiments.configuration
                    if c.design.design_ref == candidate.experiment_ref
                )
                if any(
                    c.design.design_ref != source.design.design_ref
                    and set(c.binding_refs).intersection(source.binding_refs)
                    and parsed(c.design.exposure_start)
                    <= parsed(now)
                    < parsed(c.design.readout_horizon)
                    for c in experiments.configuration
                ):
                    reason = "new_holdout"
            rows.append(
                dict(
                    candidate_ref=candidate.candidate_ref,
                    status="stop" if reason else "review_current",
                    reason=reason,
                    budget=trial["budget"],
                    execution_authorized=False,
                    spend_guard="existing_growth_envelope_authority_required",
                )
            )
        observation = dict(observed_at=self.host._now(now), trials=rows, execution_authorized=False)
        self.events.change(ref, lambda row: row.update(observation=observation), fence)
        return observation

    def unregister(self, allocation_ref, *, fence):
        def remove(doc):
            doc["refs"] = [ref for ref in doc.get("refs", []) if ref != allocation_ref]

        self.events.change(self.prefix + "index", remove, fence)

    def tick(self, *, now, fence, max_proposals=1):
        from lightbulb.company_host_journal import HostAuthorityError

        require(
            type(max_proposals) is int and 1 <= max_proposals <= 10,
            "CUSTOMER_ALLOCATION_TICK_LIMIT",
        )
        index = self.events.read(self.prefix + "index") or {}
        refs = index.get("refs", [])
        cursor = index.get("cursor", 0) % max(1, len(refs))
        selected = (refs[cursor:] + refs[:cursor])[:max_proposals]
        lifecycle = self.host.customer_lifecycle
        experiments = getattr(lifecycle, "experiments", None) if lifecycle else None
        if selected and experiments is None:
            return dict(reports=[dict(status="experiment_configuration_required")], poll_again=True)
        rows = []
        for ref in selected:
            try:
                rows.append(self.observe(ref, experiments=experiments, now=now, fence=fence))
            except (ValueError, LookupError) as error:
                if isinstance(error, HostAuthorityError):
                    raise
                rows.append(
                    dict(
                        allocation_ref=ref,
                        status="stop",
                        reason=getattr(error, "code", "evidence_unavailable"),
                    )
                )
        if selected:
            self.events.change(
                self.prefix + "index",
                lambda doc: doc.update(cursor=(cursor + len(selected)) % len(refs)),
                fence,
            )
        return dict(reports=rows, poll_again=bool(refs))
