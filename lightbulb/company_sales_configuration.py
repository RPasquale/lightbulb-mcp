"""Bounded company sales configuration shared by offline preflight and workers."""
from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from lightbulb.billing_followup import BillingRecoveryPolicy
from lightbulb.company_customer_actions import CustomerActionPolicy
from lightbulb.company_engine_core import StrictModel, detached, stable_digest
from lightbulb.company_sales_intake import SalesIntakeCandidate
from lightbulb.company_sales_playbooks import (
    SalesPlaybook, SalesProspectBinding, bind_sales_playbook, compile_sales_playbook,
)


class SalesConfigurationError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise SalesConfigurationError(code)


class CompanySalesConfiguration(StrictModel):
    customer_actions: CustomerActionPolicy = Field(default_factory=CustomerActionPolicy)
    playbooks: tuple[SalesPlaybook, ...] = Field(default_factory=tuple, max_length=20)
    bindings: tuple[SalesProspectBinding, ...] = Field(default_factory=tuple, max_length=100)
    intake_candidates: tuple[SalesIntakeCandidate, ...] = Field(default_factory=tuple, max_length=100)
    billing_policies: tuple[BillingRecoveryPolicy, ...] = Field(default_factory=tuple, max_length=100)

    @field_validator("playbooks", mode="before")
    @classmethod
    def _playbooks(cls, values):
        _require(isinstance(values, (list, tuple)) and len(values) <= 20, "SALES_PLAYBOOKS_INVALID")
        return tuple(SalesPlaybook.model_validate(detached(value))
                     if "playbook_digest" in detached(value) else compile_sales_playbook(value)
                     for value in values)

    @model_validator(mode="after")
    def _unique(self):
        self.customer_actions.validate_priorities()
        for rows, name in ((self.playbooks, "playbook_ref"), (self.bindings, "binding_ref"),
                           (self.intake_candidates, "candidate_ref"), (self.billing_policies, "policy_ref")):
            refs = [row.spec.playbook_ref if name == "playbook_ref" else getattr(row, name) for row in rows]
            _require(len(set(refs)) == len(refs), "SALES_CONFIGURATION_DUPLICATE")
        bindings = self.all_bindings()
        _require(len(bindings) <= 100, "SALES_BINDING_CAPACITY")
        _require(len({binding.prospect_ref for binding in bindings}) == len(bindings), "SALES_PROSPECT_DUPLICATE")
        _require(len({binding.endpoint_digest for binding in bindings}) == len(bindings), "SALES_ENDPOINT_DUPLICATE")
        return self

    def all_bindings(self):
        bindings = {binding.binding_ref: binding for binding in self.bindings}
        for candidate in self.intake_candidates:
            binding = candidate.binding
            _require(binding.binding_ref not in bindings or bindings[binding.binding_ref] == binding,
                     "SALES_BINDING_CONFLICT")
            bindings[binding.binding_ref] = binding
        return tuple(bindings.values())

    @property
    def configuration_digest(self):
        return stable_digest(self.to_dict())


def validate_sales_configuration(configuration, *, bundle, sources):
    """Validate declarations without claiming current consent, approval or host readiness."""
    parsed = CompanySalesConfiguration.model_validate(detached(configuration))
    playbooks = {playbook.spec.playbook_ref: playbook for playbook in parsed.playbooks}
    policies = {policy.policy_ref: policy for policy in parsed.billing_policies}
    source_map = {source.source_ref: source for source in sources}
    for policy in parsed.billing_policies:
        _require(policy.source_ref in source_map and source_map[policy.source_ref].kind == "invoice_health",
                 "SALES_BILLING_SOURCE_REQUIRED")
    for binding in parsed.all_bindings():
        _require(binding.playbook_ref in playbooks, "SALES_PLAYBOOK_REQUIRED")
        _require(binding.thread_ref is not None, "SALES_EXISTING_THREAD_REQUIRED")
        bind_sales_playbook(playbooks[binding.playbook_ref], binding, bundle)
        if binding.billing_guard is not None:
            guard = binding.billing_guard
            _require(guard.policy_ref in policies and policies[guard.policy_ref].source_ref == guard.source_ref,
                     "SALES_BILLING_POLICY_MISMATCH")
            source = source_map[guard.source_ref]
            _require(source.identity_links[source.arguments["customer_id"]] == binding.account_ref,
                     "SALES_BILLING_ACCOUNT_MISMATCH")
    if parsed.all_bindings():
        from lightbulb.company_chain_catalog import plan_for_chain
        plan_for_chain(bundle, "contact_endpoint")
    return parsed


__all__ = ["CompanySalesConfiguration", "SalesConfigurationError", "validate_sales_configuration"]
