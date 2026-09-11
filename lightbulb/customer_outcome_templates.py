"""Portable, non-causal outcome evidence and bounded destination trials."""

from typing import Literal
from pydantic import Field, model_validator
from lightbulb.company_engine_core import (
    StrictModel,
    OpaqueRef,
    Sha256Digest,
    parsed,
    stable_digest,
    timestamp,
)
from lightbulb.company_customer_events import require


class CustomerOutcomeTrial(StrictModel):
    trial_ref: OpaqueRef
    starts_at: str
    ends_at: str
    max_enrollments: int = Field(ge=1, le=100, strict=True)
    max_total_touches: int = Field(ge=1, le=1000, strict=True)
    source_template_digest: Sha256Digest
    adaptation_evidence_refs: tuple[OpaqueRef, ...] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def bounded(self):
        timestamp(self.starts_at, field_name="starts_at")
        timestamp(self.ends_at, field_name="ends_at")
        require(
            0 < (parsed(self.ends_at) - parsed(self.starts_at)).total_seconds() <= 90 * 86400,
            "CUSTOMER_TRIAL_WINDOW_INVALID",
        )
        return self


class CustomerOutcomeTemplate(StrictModel):
    schema_id: Literal["lightbulb.customer_outcome_template.v1"] = (
        "lightbulb.customer_outcome_template.v1"
    )
    goal: Literal["activation", "expansion", "inbound", "renewal"]
    outcome_kind: Literal["activated", "expanded", "meeting_booked", "subscription_retained"]
    enrolled_count: int = Field(ge=1, le=100, strict=True)
    observed_success_count: int = Field(ge=1, le=100, strict=True)
    source_evidence_digest: Sha256Digest
    max_trial_days: int = Field(ge=1, le=90, strict=True)
    max_touches_per_customer: int = Field(ge=1, le=10, strict=True)
    evidence_basis: Literal["observed_after_intervention"] = "observed_after_intervention"
    causal_uplift_verified: Literal[False] = False
    destination_revalidation_required: Literal[True] = True
    execution_authorized: Literal[False] = False
    template_digest: Sha256Digest


def export_customer_outcome_template(lifecycle, goal, *, now):
    from lightbulb.company_customer_lifecycle import CompanyCustomerLifecycle
    from lightbulb.company_sales_host import TOUCH_SCHEMA

    require(isinstance(lifecycle, CompanyCustomerLifecycle), "CUSTOMER_OUTCOME_HOST_REQUIRED")
    rows = [r for r in lifecycle.configuration.enrollments if r.goal == goal]
    require(bool(rows), "CUSTOMER_OUTCOME_COHORT_REQUIRED")
    evidence = []
    successes = 0
    expected = {
        "activation": "activated",
        "expansion": "expanded",
        "inbound": "meeting_booked",
        "renewal": "subscription_retained",
    }[goal]
    for row in rows:
        doc = lifecycle.events.read(lifecycle.ref(row))
        require(doc and doc.get("candidate"), "CUSTOMER_OUTCOME_COHORT_INCOMPLETE")
        require(
            doc["configuration_digest"] == stable_digest(row.to_dict()),
            "CUSTOMER_OUTCOME_CONFIGURATION_CHANGED",
        )
        binding = lifecycle.sales.progression.binding(row.binding_ref)
        first = lifecycle.sales._read(lifecycle.sales._ref(binding) + "-1", TOUCH_SCHEMA)
        outcome = doc.get("outcome")
        # Include every configured customer, including unsuccessful completed trials.
        require(
            outcome or parsed(now) >= parsed(doc["candidate"]["expires_at"]),
            "CUSTOMER_OUTCOME_TRIAL_INCOMPLETE",
        )
        if outcome:
            require(
                first
                and first["phase"] == "applied"
                and stable_digest(first["effect"]) == outcome["effect_digest"],
                "CUSTOMER_OUTCOME_EFFECT_REQUIRED",
            )
            require(
                outcome["kind"] == expected
                and parsed(first["effect"]["completed_at"])
                <= parsed(outcome["observed_at"])
                <= parsed(now),
                "CUSTOMER_OUTCOME_TIME_MISMATCH",
            )
            if goal == "renewal":
                from lightbulb.customer_renewal_outcomes import verified_renewal_outcome

                require(
                    verified_renewal_outcome(lifecycle, row, first, now=now) == outcome,
                    "CUSTOMER_OUTCOME_RENEWAL_REQUIRED",
                )
            elif goal == "inbound":
                proposal = lifecycle.sales.progression.read(outcome["event_ref"])
                status = lifecycle.sales.progression.meetings.status(
                    binding.binding_ref, outcome["event_ref"]
                )
                require(
                    status["action"] == "meeting_recorded"
                    and stable_digest(proposal["verified"]) == outcome["evidence_digest"],
                    "CUSTOMER_OUTCOME_MEETING_REQUIRED",
                )
            else:
                source = lifecycle.events.read(outcome["event_ref"])
                require(
                    source
                    and stable_digest(source["event"]) == outcome["evidence_digest"]
                    and source["event"]["account_ref"] == binding.account_ref
                    and source["event"]["kind"] == expected,
                    "CUSTOMER_OUTCOME_EVENT_REQUIRED",
                )
            successes += 1
        evidence.append(
            {
                "enrollment": stable_digest(row.to_dict()),
                "record": stable_digest(doc),
                "touch": stable_digest(first) if first else None,
            }
        )
    require(successes > 0, "CUSTOMER_OUTCOME_SUCCESS_REQUIRED")
    body = {
        "schema_id": "lightbulb.customer_outcome_template.v1",
        "goal": goal,
        "outcome_kind": expected,
        "enrolled_count": len(rows),
        "observed_success_count": successes,
        "source_evidence_digest": stable_digest(evidence),
        "max_trial_days": min(r.trial_days for r in rows),
        "max_touches_per_customer": min(r.max_touches for r in rows),
        "evidence_basis": "observed_after_intervention",
        "causal_uplift_verified": False,
        "destination_revalidation_required": True,
        "execution_authorized": False,
    }
    return CustomerOutcomeTemplate(**body, template_digest=stable_digest(body))


def instantiate_customer_outcome_trial(template, sales, sources, configuration, trial):
    """Return a proposal using fresh destination identities, copy, sources and approvals.

    Imported evidence is a candidate-selection aid; its digest is integrity, not
    cross-company authority or causal certification.
    """
    from lightbulb.company_customer_lifecycle import CustomerLifecycleConfiguration

    template = CustomerOutcomeTemplate.model_validate(template)
    require(
        template.template_digest
        == stable_digest(template.model_dump(mode="json", exclude={"template_digest"})),
        "CUSTOMER_TEMPLATE_DIGEST_MISMATCH",
    )
    require(
        template.observed_success_count <= template.enrolled_count,
        "CUSTOMER_TEMPLATE_COUNTS_INVALID",
    )
    trial = CustomerOutcomeTrial.model_validate(trial)
    require(
        trial.source_template_digest == template.template_digest, "CUSTOMER_TRIAL_TEMPLATE_MISMATCH"
    )
    config = CustomerLifecycleConfiguration.model_validate(
        {**dict(configuration), "trial": trial}
    ).validate_bindings(sales, sources)
    require(
        bool(config.enrollments) and len(config.enrollments) <= trial.max_enrollments,
        "CUSTOMER_TRIAL_COHORT_INVALID",
    )
    require(
        (parsed(trial.ends_at) - parsed(trial.starts_at)).total_seconds()
        <= template.max_trial_days * 86400,
        "CUSTOMER_TRIAL_WINDOW_EXCEEDED",
    )
    require(
        all(
            r.goal == template.goal
            and r.max_touches <= template.max_touches_per_customer
            and r.trial_days <= template.max_trial_days
            for r in config.enrollments
        ),
        "CUSTOMER_TRIAL_LIMIT_EXCEEDED",
    )
    return config


def trial_stop_reason(lifecycle, now):
    trial = lifecycle.configuration.trial
    if trial is None:
        return None
    if parsed(now) < parsed(trial.starts_at):
        return "trial_not_started"
    if parsed(now) >= parsed(trial.ends_at):
        return "trial_expired"
    touches = 0
    for row in lifecycle.configuration.enrollments:
        binding = lifecycle.sales.progression.binding(row.binding_ref)
        if lifecycle.sales.runner.store.get("pipeline_engine", binding.prospect_ref):
            touches += lifecycle.sales._state(binding).ledger.touches
    return "trial_touch_limit" if touches >= trial.max_total_touches else None
